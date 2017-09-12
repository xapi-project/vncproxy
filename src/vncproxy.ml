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

open Lwt.Infix
open Xen_api
open Xen_api_lwt_unix

let exn_to_string = function
  | Api_errors.Server_error(code, params) ->
    Printf.sprintf "%s %s" code (String.concat " " params)
  | e -> Printexc.to_string e

let find_console rpc session_id x =
  Lwt_io.eprintlf "Trying to find console for VM %s" x >>= fun () ->
  (* Treat 'x' first as a uuid and then as a name_label *)
  Lwt.catch
    (fun () -> VM.get_by_uuid ~rpc ~session_id ~uuid:x )
    (fun  _ ->
       VM.get_by_name_label ~rpc ~session_id ~label:x >>= function
       | [ exactly_one ] -> Lwt.return exactly_one
       | [] ->
         Lwt_io.eprintlf "Failed to find VM %s" x >>= fun () ->
         Lwt.fail_with (Printf.sprintf "Failed to find VM %s" x)
       | y :: _ ->
         VM.get_uuid ~rpc ~session_id ~self:y >>= fun uuid ->
         Lwt_io.eprintlf "More than one VM found with this name" >>= fun () ->
         Lwt_io.eprintlf "Choosing VM with uuid %s" uuid >>= fun () ->
         Lwt.return y
    )
  >>= fun vm ->
  (* Check that the VM is running *)
  VM.get_power_state ~rpc ~session_id ~self:vm
  >>= fun power_state ->
  (if power_state <> `Running then begin
      Lwt_io.eprintlf "The VM %s is not running" vm >>= fun () ->
      Lwt.fail_with "The VM is not running"
    end else Lwt.return_unit) >>= fun () ->

  (* Find a console with the RFB protocol *)
  VM.get_consoles ~rpc ~session_id ~self:vm >>= fun cs ->
  Lwt_list.filter_map_s (fun c ->
      Lwt.catch
        (fun () ->
           Console.get_record ~rpc ~session_id ~self:c
           >>= fun c_record ->
           if c_record.API.console_protocol = `rfb
           then Lwt.return_some c_record
           else Lwt.return_none)
        (fun e ->
          (* Lwt_io.eprintlf "warning: %s" (Printexc.to_string e) >>= fun () -> *)
          Lwt.return_none)
    ) cs >>= fun all -> 
  match all with
  | [ exactly_one ] -> Lwt.return exactly_one
  | [] ->
    Lwt_io.eprintlf "The VM is exposing no VNC consoles" >>= fun () ->
    Lwt.fail_with "The VM is exposing no VNC consoles"
  | y :: _ ->
    Lwt_io.eprintlf "The VM is exposing multiple VNC consoles" >>= fun () ->
    Lwt_io.eprintlf "I will choose one for you" >>= fun () ->
    Lwt.return y
    >>= fun console ->
    Lwt_io.eprintlf "Found console %s" console.API.console_uuid >>= fun () ->
    Lwt.return console


let bind_local_port () =
  let sockaddr = Unix.ADDR_INET(Unix.inet_addr_of_string "127.0.0.1", 0) in
  let sock = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.setsockopt sock Unix.SO_REUSEADDR true;
  Unix.bind sock sockaddr;
  Unix.listen sock 5;

  (* Determine the local port in use *)
  match Unix.getsockname sock with
  | Unix.ADDR_INET(_, port) ->
    Lwt.return (sock, port)
  | _ -> assert false

let connect_to_console session_id console =
  Lwt_io.eprintlf "Trying to connect to console %s" console.API.console_uuid >>= fun () ->
  let uri = Uri.of_string console.API.console_location in
  Xen_api_lwt_unix.Lwt_unix_IO.open_connection uri >>= function
  | Ok ((_, ic), (_, oc)) ->
    Lwt_io.write oc (Printf.sprintf "CONNECT %s?%s HTTP/1.0\r\n" (Uri.path uri) (Uri.(encoded_of_query (query uri)))) >>= fun () ->
    Lwt_io.write oc (Printf.sprintf "Cookie: session_id=%s\r\n" (API.Ref.string_of session_id)) >>= fun () ->
    Lwt_io.write oc "\r\n" >>= fun () ->
    Lwt_io.flush oc >>= fun ()->
    Lwt_io.read_line ic
    >>= fun status ->
    Lwt_io.eprintlf "%s" status >>= fun () ->
    let rec loop finished =
      if finished then
        Lwt.return_unit
      else begin
        Lwt_io.read_line ic 
        >>= fun line ->
        Lwt_io.eprintlf "%s" line >>= fun () ->
        loop (line = "")
      end
    in
    loop false >>= fun () -> Lwt.return (ic, oc)
  | Error e -> Lwt.fail e

let proxy (a_ic, a_oc) (b_ic, b_oc) =
  Lwt_io.eprintlf "Starting to proxy" >>= fun () ->
  let copy x y =
    Lwt.catch
      (fun () ->
         let rec loop () =
           Lwt_io.read_char x >>= fun c ->
           Lwt_io.write_char y c >>=
           loop
         in
         loop ()
      )
      (function | End_of_file -> Lwt.return_unit | e -> Lwt.fail e)
  in
  let _ = copy a_ic b_oc in
  let _ = copy b_ic a_oc in
  Lwt.return_unit

let connect c x =
  let rpc = make c.Common.uri in
  let intercept_exit vncviewer = vncviewer >>= function
    | Unix.WEXITED 0 -> Lwt.return_unit
    | Unix.WEXITED n ->
      Lwt_io.eprintlf "vncviewer non-zero exit code: %d" n
    | Unix.WSIGNALED n ->
      Lwt_io.eprintlf "vncviewer signalled with %d" n
    | Unix.WSTOPPED n ->
      Lwt_io.eprintlf "vncviewer stopped with %d" n
  in
  Session.login_with_password ~rpc ~uname:c.Common.username ~pwd:c.Common.password ~version:"1.0" ~originator:"vncproxy"
  >>= fun session_id ->
  Lwt_io.eprintlf "Got session %s" session_id >>= fun () ->
  Lwt.finalize
    (fun () ->
       Lwt.catch
         (fun () ->
            find_console rpc session_id x >>= fun console ->
            connect_to_console session_id console >>= fun remote ->
            bind_local_port () >>= fun (listening_sock, port) ->
            let vncviewer = Lwt_unix.system (Printf.sprintf "vncviewer localhost:%d" port) in
            let connected_sock, _ = Unix.accept listening_sock in
            let ic = Lwt_io.of_unix_fd ~mode:Lwt_io.input connected_sock in
            let oc = Lwt_io.of_unix_fd ~mode:Lwt_io.output connected_sock in
            Lwt_io.eprintlf "Ready to proxy" >>= fun () ->
            ignore(proxy (ic, oc) remote);
            intercept_exit vncviewer)
         (fun _ -> Lwt.return_unit)
    )
    (fun () -> Session.logout ~rpc ~session_id)

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

