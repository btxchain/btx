; Atlas overrides for Tauri CLI 2.12.4 association helpers.
; Source: https://github.com/tauri-apps/tauri/blob/tauri-cli-v2.12.4/crates/tauri-bundler/src/bundle/windows/nsis/FileAssociation.nsh
; Original helpers by Saivert, improved by Nikku.
; SPDX-License-Identifier: MIT
;
; MIT License
;
; Copyright (c) 2017 - Present Tauri Apps Contributors
;
; Permission is hereby granted, free of charge, to any person obtaining a copy
; of this software and associated documentation files (the "Software"), to deal
; in the Software without restriction, including without limitation the rights
; to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
; copies of the Software, and to permit persons to whom the Software is
; furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in all
; copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
; AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
; OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
; SOFTWARE.
;
; Keep the generated installer and its remaining lifecycle logic unchanged.
!include LogicLib.nsh

!ifmacrodef APP_ASSOCIATE
  !macroundef APP_ASSOCIATE
!endif
!macro APP_ASSOCIATE EXT FILECLASS DESCRIPTION ICON COMMANDTEXT COMMAND
  ReadRegStr $R0 SHELL_CONTEXT "Software\Classes\.${EXT}" ""
  ; A reinstall must not replace the original backup with our own class.
  ${If} $R0 != "${FILECLASS}"
    WriteRegStr SHELL_CONTEXT "Software\Classes\.${EXT}" "${FILECLASS}_backup" "$R0"
  ${EndIf}
  WriteRegStr SHELL_CONTEXT "Software\Classes\.${EXT}" "" "${FILECLASS}"
  WriteRegStr SHELL_CONTEXT "Software\Classes\${FILECLASS}" "" `${DESCRIPTION}`
  WriteRegStr SHELL_CONTEXT "Software\Classes\${FILECLASS}\DefaultIcon" "" `${ICON}`
  WriteRegStr SHELL_CONTEXT "Software\Classes\${FILECLASS}\shell" "" "open"
  WriteRegStr SHELL_CONTEXT "Software\Classes\${FILECLASS}\shell\open" "" `${COMMANDTEXT}`
  WriteRegStr SHELL_CONTEXT "Software\Classes\${FILECLASS}\shell\open\command" "" `${COMMAND}`
!macroend

!ifmacrodef APP_UNASSOCIATE
  !macroundef APP_UNASSOCIATE
!endif
!macro APP_UNASSOCIATE EXT FILECLASS
  ReadRegStr $R0 SHELL_CONTEXT "Software\Classes\.${EXT}" ""
  ; A later handler selection belongs to its new owner.
  ${If} $R0 == "${FILECLASS}"
    ReadRegStr $R0 SHELL_CONTEXT "Software\Classes\.${EXT}" "${FILECLASS}_backup"
    ${If} $R0 == ""
    ${OrIf} $R0 == "${FILECLASS}"
      ; Older installers may already have saved a self-reference. Do not
      ; restore a class that this uninstall is about to remove.
      DeleteRegValue SHELL_CONTEXT "Software\Classes\.${EXT}" ""
    ${Else}
      WriteRegStr SHELL_CONTEXT "Software\Classes\.${EXT}" "" "$R0"
    ${EndIf}
  ${EndIf}
  DeleteRegValue SHELL_CONTEXT "Software\Classes\.${EXT}" "${FILECLASS}_backup"
  DeleteRegKey SHELL_CONTEXT "Software\Classes\${FILECLASS}"
!macroend
