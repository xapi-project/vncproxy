(*
 * Copyright (c) Citrix Systems Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms,
 * with or without modification, are permitted provided
 * that the following conditions are met:
 *
 * *   Redistributions of source code must retain the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer.
 * *   Redistributions in binary form must reproduce the above
 *     copyright notice, this list of conditions and the
 *     following disclaimer in the documentation and/or other
 *     materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND
 * CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *)

let project_url = "http://github.com/xapi-project/vncproxy"

module Common = struct
  type t = {
    debug: bool;
    uri: string;
    username: string;
    password: string;
  }
  let make debug uri' username' password' =
    (* Built-in defaults: *)
    let uri = "https://127.0.0.1" in
    let username = "root" in
    let password = "" in
    (* TODO: read overrides from a config file *)
    let default d = function None -> d | Some x -> x in
    let uri = default uri uri' in
    let username = default username username' in
    let password = default password password' in
    { debug; uri; username; password }
end

open Lwt
open Xen_api
open Xen_api_lwt_unix

let exn_to_string = function
  | Api_errors.Server_error(code, params) ->
    Printf.sprintf "%s %s" code (String.concat " " params)
  | e -> Printexc.to_string e

let find_console rpc session_id x =
  (* Treat 'x' first as a uuid and then as a name_label *)
  let%lwt vm =
    try%lwt
      VM.get_by_uuid rpc session_id x
    with _ ->
      let%lwt possibilities = VM.get_by_name_label rpc session_id x in
      match possibilities with
      | [ exactly_one ] -> return exactly_one
      | [] ->
        Printf.fprintf stderr "Failed to find VM %s\n%!" x;
        fail (Failure (Printf.sprintf "Failed to find VM %s" x))
      | x :: too_many ->
        let%lwt uuid = VM.get_uuid rpc session_id x in
        Printf.fprintf stderr "More than one VM found with this name.\n%!";
        Printf.fprintf stderr "Choosing VM with uuid %s.\n%!" uuid;
        return x in
  (* Check that the VM is running *)
  let%lwt power_state = VM.get_power_state rpc session_id vm in
  let%lwt () =
    if power_state <> `Running then begin
      Printf.fprintf stderr "The VM %s is not running.\n%!" vm;
      fail (Failure (Printf.sprintf "The VM is not running"))
    end else return () in
  (* Find a console with the RFB protocol *)
  let%lwt console =
    let%lwt all = VM.get_consoles rpc session_id vm in
    let%lwt all = Lwt_list.map_s (fun c -> Console.get_record rpc session_id c) all in
    match List.filter (fun c -> c.API.console_protocol = `rfb) all with
    | [ exactly_one ] -> return exactly_one
    | [] ->
      Printf.fprintf stderr "The VM is exposing no VNC consoles.\n%!";
      fail (Failure (Printf.sprintf "The VM is exposing no VNC consoles"))
    | x :: too_many ->
      Printf.fprintf stderr "The VM is exposing multiple VNC consoles.\n";
      Printf.fprintf stderr "I will choose one for you.\n%!";
      return x
  in
  return console

let bind_local_port () =
  let sockaddr = Unix.ADDR_INET(Unix.inet_addr_of_string "127.0.0.1", 0) in
  let sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.setsockopt sock Unix.SO_REUSEADDR true;
  Unix.bind sock sockaddr;
  Unix.listen sock 5;

  (* Determine the local port in use *)
  match Unix.getsockname sock with
  | Unix.ADDR_INET(_, port) ->
(*
      let ic = Lwt_io.of_unix_fd ~mode:Lwt_io.input sock in
      let oc = Lwt_io.of_unix_fd ~mode:Lwt_io.output sock in
      (ic, oc),
*)
    sock, port
  | _ -> assert false

let connect_to_console session_id console =
  let uri = Uri.of_string console.API.console_location in
  match%lwt Xen_api_lwt_unix.Lwt_unix_IO.open_connection uri with
  | Ok ((_, ic), (_, oc)) ->
    let%lwt () = Lwt_io.write oc (Printf.sprintf "CONNECT %s?%s HTTP/1.0\r\n" (Uri.path uri) (Uri.(encoded_of_query (query uri)))) in
    let%lwt () = Lwt_io.write oc (Printf.sprintf "Cookie: session_id=%s\r\n" (API.Ref.string_of session_id)) in
    let%lwt () = Lwt_io.write oc "\r\n" in
    let%lwt () = Lwt_io.flush oc in
    let%lwt status = Lwt_io.read_line ic in
    Printf.fprintf stderr "%s\n%!" status;
    let rest = ref [] in
    let finished = ref false in
    let%lwt () = while%lwt not !finished do
        let%lwt line = Lwt_io.read_line ic in
        Printf.fprintf stderr "%s\n%!" line;
        if line = ""
        then finished := true
        else rest := line :: !rest;
        return ()
      done in
    return (ic, oc)
  | Error e -> fail e

let proxy (a_ic, a_oc) (b_ic, b_oc) =
  let copy x y =
    try%lwt
      while%lwt true do
        let%lwt c = Lwt_io.read_char x in
        Lwt_io.write_char y c
      done
    with End_of_file -> return () in
  let _ = copy a_ic b_oc in
  let _ = copy b_ic a_oc in
  ()

let connect c x =
  let rpc = make c.Common.uri in
  let%lwt session_id = Session.login_with_password rpc c.Common.username c.Common.password "1.0" "vncproxy" in
  let intercept_exit vncviewer = match%lwt vncviewer with
    | Unix.WEXITED 0 -> return ()
    | Unix.WEXITED n ->
      Printf.fprintf stderr "vncviewer non-zero exit code: %d" n;
      return ()
    | Unix.WSIGNALED n ->
      Printf.fprintf stderr "vncviewer signalled with %d" n;
      return ()
    | Unix.WSTOPPED n ->
      Printf.fprintf stderr "vncviewer stopped with %d" n;
      return ()
  in
  begin
    try%lwt
      let%lwt console = find_console rpc session_id x in
      let%lwt remote = connect_to_console session_id console in
      let listening_sock, port = bind_local_port () in
      let vncviewer = Lwt_unix.system (Printf.sprintf "vncviewer localhost:%d" port) in
      let connected_sock, _ = Unix.accept listening_sock in
      let ic = Lwt_io.of_unix_fd ~mode:Lwt_io.input connected_sock in
      let oc = Lwt_io.of_unix_fd ~mode:Lwt_io.output connected_sock in
      proxy (ic, oc) remote;
      intercept_exit vncviewer
    with _ -> return_unit
  end [%finally Session.logout rpc session_id]

let connect common = function
  | None ->
    `Error(true, "You must supply either a VM name-label or uuid")
  | Some x ->
    `Ok (Lwt_main.run (connect common x))

open Cmdliner

let _common_options = "COMMON OPTIONS"
let help = [
  `S _common_options;
  `P "These options are common to all commands.";
  `S "MORE HELP";
  `P "Use `$(mname) $(i,COMMAND) --help' for help on a single command."; `Noblank;
  `S "BUGS"; `P (Printf.sprintf "Check bug reports at %s" project_url);
]

(* Options common to all commands *)
let common_options_t =
  let docs = _common_options in
  let debug =
    let doc = "Give only debug output." in
    Arg.(value & flag & info ["debug"] ~docs ~doc) in
  let uri =
    let doc = "URI of XenServer" in
    Arg.(value & opt (some string) None & info["uri"] ~docs ~doc) in
  let username =
    let doc = "Username to login as" in
    Arg.(value & opt (some string) None & info["username"] ~docs ~doc) in
  let password =
    let doc = "Password to use" in
    Arg.(value & opt (some string) None & info["password"] ~docs ~doc) in
  Term.(pure Common.make $ debug $ uri $ username $ password)

let connect_cmd =
  let doc = "connect to a running VM's VNC console" in
  let man = [
    `S "DESCRIPTION";
    `P "Runs a local vncviewer and connects it to a running VM's VNC console through the secure tunnel";
  ] @ help in
  let vm =
    let doc = Printf.sprintf "VM name-label or uuid" in
    Arg.(value & pos 0 (some string) None & info [] ~doc) in
  Term.(ret(pure connect $ common_options_t $ vm)),
  Term.info "connect" ~sdocs:_common_options ~doc ~man

let default_cmd =
  let doc = "interact with remote XenServer VM consoles" in
  let man = help in
  Term.(ret (pure (fun _ -> `Help (`Pager, None)) $ common_options_t)),
  Term.info "vncproxy" ~version:"1.0.0" ~sdocs:_common_options ~doc ~man

let cmds = [connect_cmd]

let _ =
  match Term.eval_choice default_cmd cmds with
  | `Error _ -> exit 1
  | _ -> exit 0

