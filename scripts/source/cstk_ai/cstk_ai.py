#!/usr/bin/env python3
"""CSTK AI TUI V2: provider-neutral, explicit-context AI client."""
from __future__ import annotations
import shlex
import json
import os
import re
from pathlib import Path
from textual import events, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Footer, Input, Label, ListItem, ListView, RichLog, Static
from provider_client import ChatMessage, prepare_chat_request
from provider_config import ProviderConfig, ProviderConfigError, load_provider, save_provider
from provider_transport import ProviderTransportError, send_prepared_request
from engagement_phase2 import BridgeError, Phase2Bridge

COMMANDS={"/help":"commands and shortcuts","/provider":"NAME URL MODEL [KEY_ENV]","/credential":"KEY_ENV (hidden, session only)","/model":"select model","/connection":"safe connection summary","/engagement":"list|use ID|show|progress|next|answer TAG TEXT|candidate","/save-provider":"save non-secret profile","/load-provider":"load profile","/scope":"legacy session scope","/privacy":"transmission rules","/clear":"clear chat","/exit":"quit"}
CONTEXTS={"@engagement":"confirmed engagement summary","@scope":"authorization scope","@session":"safe provider metadata","@privacy":"transmission policy"}
PALETTE=[("Help","/help"),("Configure provider","/provider "),("Enter session credential","/credential "),("Select model","/model "),("Connection details","/connection"),("Set scope","/scope "),("Privacy","/privacy"),("Clear","/clear")]

class CredentialScreen(ModalScreen[str|None]):
    CSS="""CredentialScreen{align:center middle;background:#000000}#credential-box{width:72;height:11;border:heavy #ff8700;background:#101010;padding:1 2}#secret{border:tall #00d7ff;margin-top:1}"""
    BINDINGS=[Binding("escape","cancel","Cancel",priority=True)]
    def __init__(self,env_name): super().__init__(); self.env_name=env_name
    def compose(self)->ComposeResult:
        with Vertical(id="credential-box"):
            yield Label(f"SESSION CREDENTIAL  [bold #00d7ff]{self.env_name}[/]\nValue is hidden, never saved, and cleared when CSTK AI exits.")
            yield Input(placeholder="Enter provider key…",password=True,id="secret")
    def on_mount(self): self.query_one("#secret",Input).focus()
    def on_input_submitted(self,event:Input.Submitted):
        value=event.value; event.input.value=""; self.dismiss(value or None)
    def action_cancel(self): self.dismiss(None)

class Palette(ModalScreen[str|None]):
    CSS="""Palette{align:center middle;background:#000000}#box{width:72;height:22;border:heavy #00d7ff;background:#101010;padding:1 2}#filter{border:tall #ff8700}ListView{height:1fr}ListItem.--highlight{background:#005f5f}"""
    def compose(self)->ComposeResult:
        with Vertical(id="box"):
            yield Label("CSTK ACTION PALETTE  Ctrl+K")
            yield Input(placeholder="Filter actions…",id="filter")
            yield ListView(id="list")
    def on_mount(self): self._fill(""); self.query_one("#filter",Input).focus()
    def _fill(self,q):
        view=self.query_one("#list",ListView); view.clear()
        for label,cmd in PALETTE:
            if q.lower() in (label+cmd).lower():
                item=ListItem(Label(f"[bold #00d7ff]{cmd}[/]  {label}")); item.data=cmd; view.append(item)
    def on_input_changed(self,event:Input.Changed): self._fill(event.value)
    def on_list_view_selected(self,event:ListView.Selected): self.dismiss(getattr(event.item,"data",None))

class CSTKAnalystV2(App):
    TITLE="CSTK AI Analyst V2"
    BINDINGS=[
        Binding("ctrl+q","quit","Quit",priority=True),
        Binding("ctrl+l","clear_chat","Clear",priority=True),
        Binding("f1","help","Help",priority=True),
        Binding("ctrl+k","palette","Palette",priority=True),
    ]
    CSS="""
    Screen{background:#060606;color:#d7d7d7}#head{height:3;padding:1 2;color:#ffaf00;text-style:bold;border-bottom:heavy #ff8700}
    #safety-strip{height:auto;max-height:3;padding:0 2;background:#003f3f;color:#ffffff;text-style:bold}
    #work{height:1fr;padding:1}#left,#right{width:27;border:round #008787;padding:1;background:#080808}#middle{width:1fr;margin:0 1}
    #chat{height:1fr;border:heavy #005f5f;padding:1 2;background:#101010}#suggest{display:none;height:auto;max-height:10;border:tall #00d7ff;padding:0 1;background:#101010}
    #suggest.visible{display:block}#prompt{height:3;border:heavy #ff8700;margin-top:1}Footer{background:#080808}
    """
    def __init__(self):
        super().__init__(); self.provider=None; self.scope="not set"; self.messages=[]; self.engagement_id=None
        self._session_credentials=set()
        self.connection_state="NOT CONFIGURED"; self._last_hud_safety=None
        self.profile=Path.home()/".config/cstk/ai/provider.json"
        try: self.engagements=Phase2Bridge()
        except Exception: self.engagements=None
    def compose(self)->ComposeResult:
        yield Static("CSTK AI ANALYST  [#00d7ff]DEFENSIVE • PRIVATE • OPERATOR CONTROLLED[/]",id="head")
        yield Static(id="safety-strip")
        with Horizontal(id="work"):
            yield Static(id="left")
            with Vertical(id="middle"):
                yield RichLog(id="chat",markup=True,wrap=True)
                yield Static(id="suggest")
                yield Input(placeholder="Ask CSTK AI…  / commands  @ context  Ctrl+K actions",id="prompt")
            yield Static(id="right")
        yield Footer()
    def on_mount(self):
        self._panels(); self.set_interval(1,self._refresh_hud); self._say("[bold #ffaf00]CSTK AI V2 ready.[/] Type /help, @, or press Ctrl+K."); self.query_one("#prompt",Input).focus()
        selected = os.environ.get("CSTK_ENGAGEMENT_SLUG")
        if selected and self.engagements:
            self._engagement(["use", selected])
        self._set_compact_layout(self.size.width)
    def on_resize(self,event:events.Resize): self._set_compact_layout(event.size.width)
    def _set_compact_layout(self,width):
        if not self.is_mounted: return
        compact=width<105
        for selector in ("#left","#right"):
            self.query_one(selector,Static).styles.display="none" if compact else "block"
        self.query_one("#middle",Vertical).styles.margin=(0,0) if compact else (0,1)
        self.query_one("#safety-strip",Static).styles.max_height=5 if compact else 3
    def _panels(self):
        p=self.provider
        self.query_one("#left",Static).update(f"[#00d7ff bold]AI CONNECTION[/]\n\nSTATE      {self.connection_state}\nPROVIDER   {p.name if p else 'NOT SET'}\nMODEL      {p.model if p else 'NOT SET'}\nKEY ENV    {p.api_key_env if p and p.api_key_env else 'NOT REQUIRED'}\nTLS        REMOTE REQUIRED\n\n[#00d7ff bold]INPUT POLICY[/]\n\nExplicit context only\nNo silent file access\nNo autonomous tools")
        self.query_one("#right",Static).update(self._hud_text())
        provider=f"{p.name}/{p.model}" if p else "NOT CONFIGURED"
        engagement="NONE • STOP / REVIEW"
        if self.engagements and self.engagement_id:
            try:
                hud=self.engagements.hud_snapshot(self.engagement_id)
                engagement=f"{hud['slug']} • {hud['state']} • {hud['timing']} • WINDOW {'OPEN' if hud['inside_testing_window'] else 'CLOSED'} • {'OPERATIONAL' if hud['operational'] else 'STOP / REVIEW'}"
            except (BridgeError,OSError,KeyError,ValueError): engagement=f"{self.engagement_id} • ERROR • STOP / REVIEW"
        self.query_one("#safety-strip",Static).update(f"AI {provider} • {self.connection_state}\nENGAGEMENT {engagement}")
    def _refresh_hud(self):
        if not self.is_mounted: return
        self._panels()
        if not self.engagements or not self.engagement_id: return
        try:
            hud=self.engagements.hud_snapshot(self.engagement_id)
            signature=(hud["state"],hud["operational"],hud["inside_testing_window"],hud["timing"] in {"EXPIRED","NOT STARTED"},hud.get("revision_sha256"))
        except (BridgeError,OSError,KeyError,ValueError): signature=("ERROR",False,False,True)
        if self._last_hud_safety is not None and signature != self._last_hud_safety:
            self.messages.clear()
            color="#5fff87" if signature[1] else "#ff5f5f"
            self._say(f"[{color} bold]ENGAGEMENT STATUS CHANGED:[/] {signature[0]} • {'OPERATIONAL' if signature[1] else 'STOP / REVIEW'}")
        self._last_hud_safety=signature
    def _hud_text(self):
        if not self.engagements or not self.engagement_id:
            return "[#ffaf00 bold]ENGAGEMENT HUD[/]\n\nSTATE      NONE\n\nUse /engagement list\nthen /engagement use ID\n\nNo engagement context\nwill be sent to AI."
        try: hud=self.engagements.hud_snapshot(self.engagement_id)
        except (BridgeError,OSError,KeyError,ValueError) as error: return f"[#ff5f5f bold]ENGAGEMENT ERROR[/]\n\n{error}"
        color="#5fff87" if hud["operational"] else "#ff5f5f"
        window="OPEN" if hud["inside_testing_window"] else "CLOSED"
        return (
            f"[#ffaf00 bold]ENGAGEMENT HUD[/]\n\n"
            f"[{color} bold]{hud['state']} • {hud['timing']}[/]\n"
            f"{hud['slug']}\n{hud['client']}\n\n"
            f"START  {hud['valid_from']}\nEND    {hud['valid_until']}\n"
            f"WINDOW {window} • {hud['timezone']}\n\n"
            f"SCOPE  +{hud['included_targets']} / -{hud['excluded_targets']}\n"
            f"ACTIONS {hud['allowed_actions']} allow • {hud['confirm_actions']} confirm\n"
            f"DENIED  {hud['denied_actions']}\n"
            f"LIMITS  {hud['max_rps']} rps • {hud['max_concurrency']} jobs\n"
            f"SOURCE  {hud['source_ip_rules']} IP rule(s)\n\n"
            f"[#ffaf00 bold]EMERGENCY[/]\n{hud['emergency_contact']}\n{hud['emergency_method']}"
        )
    def _say(self,text): self.query_one("#chat",RichLog).write(text)
    def on_input_changed(self,event:Input.Changed):
        value=event.value.lstrip(); choices={}
        if value.startswith("/"): choices={k:v for k,v in COMMANDS.items() if k.startswith(value.split()[0])}
        elif value.startswith("@"): choices={k:v for k,v in CONTEXTS.items() if k.startswith(value.split()[0])}
        box=self.query_one("#suggest",Static)
        if choices: box.update("\n".join(f"[bold #00d7ff]{k}[/]  {v}" for k,v in choices.items())); box.add_class("visible")
        else: box.remove_class("visible")
    def on_input_submitted(self,event:Input.Submitted):
        value=event.value.strip(); event.input.value=""; self.query_one("#suggest",Static).remove_class("visible")
        if value: self._command(value) if value.startswith("/") else self._send(value)
    def _command(self,value):
        try: cmd,*args=shlex.split(value)
        except ValueError as e: self._say(f"[red]Command error: {e}[/]"); return
        if cmd=="/help": self._say("\n".join(f"[bold #00d7ff]{k}[/] — {v}" for k,v in COMMANDS.items())+"\n[bold]@scope @session @privacy[/] — explicit context")
        elif cmd=="/provider": self._set_provider(args)
        elif cmd=="/credential": self._credential(args)
        elif cmd=="/model" and self.provider and args: self._change_model(" ".join(args))
        elif cmd=="/connection":
            self._say("No provider configured." if not self.provider else "\n".join(f"{k}: {v}" for k,v in self.provider.to_public_dict().items()))
        elif cmd=="/engagement": self._engagement(args)
        elif cmd=="/save-provider":
            try:
                if not self.provider: raise ProviderConfigError("configure a provider first")
                save_provider(self.provider,self.profile); self._say(f"Saved non-secret profile: {self.profile}")
            except (OSError,ProviderConfigError) as e: self._say(f"[red]Save failed: {e}[/]")
        elif cmd=="/load-provider":
            try:
                loaded=load_provider(self.profile); self._activate_provider(loaded,"loaded saved profile")
            except (OSError,ValueError,TypeError) as e: self._say(f"[red]Load failed: {e}[/]")
        elif cmd=="/scope": self._say("Scope comes from the validated engagement record. Use /engagement use ID; operator notes cannot authorize targets.")
        elif cmd=="/privacy": self._say("Only typed text and expanded @ context are sent. Keys stay in process memory, are never saved, and session-entered keys are cleared on exit. No silent file reads or authorization logging.")
        elif cmd=="/clear": self.action_clear_chat()
        elif cmd=="/exit": self.exit()
        else: self._say("Usage: /provider NAME URL MODEL [KEY_ENV]" if cmd=="/provider" else f"Unknown or incomplete command: {cmd}")
    def _engagement(self,args):
        if not args: self._say("Usage: /engagement list | use ID | show | progress | next | answer TAG TEXT | candidate"); return
        action,*rest=args
        try:
            if not self.engagements: raise BridgeError("phase-2 engagement engine is unavailable")
            if action=="list":
                rows=self.engagements.list(); self._say("No engagements found." if not rows else "\n".join(f"{row.get('slug')}  {row.get('state')}  {row.get('name')}" for row in rows))
            elif action=="use" and rest:
                item=self.engagements.detail(rest[0])
                locked=os.environ.get("CSTK_ENGAGEMENT_SLUG")
                if locked and item["config"]["slug"] != locked: raise BridgeError("switch engagements through the CSTK main manager, then reopen the AI")
                self.messages.clear(); self.engagement_id=item["config"]["slug"]; self.scope=", ".join(target["value"] for target in item["config"]["scope"]["include"]); self._last_hud_safety=None; self._refresh_hud(); self._say(f"Selected {self.engagement_id} ({item['state']}). Outbound history cleared; scope context requires current operational authorization.")
            elif action=="show" and self.engagement_id:
                item=self.engagements.detail(self.engagement_id); self._say(f"engagement: {self.engagement_id}\nstate: {item['state']}\nrevision: {item['revision']}\nsha256: {item['sha256']}\nactivation errors: {len(item['activation_errors'])}")
            elif action in {"progress","next"} and self.engagement_id:
                progress=self.engagements.questionnaire_progress(self.engagement_id)
                summary=f"Pre-engagement questionnaire: {progress['answered']}/{progress['total']} captured • {progress['status']}"
                if progress["complete"]: self._say(summary+"\nAll mandatory answers are captured for review; authorization is unchanged.")
                elif action=="next":
                    item=progress["remaining"][0]; self._say(f"{summary}\n[bold #00d7ff]{item['tag']}[/] — {item['question']}\nCapture with: /engagement answer {item['tag']} YOUR ANSWER")
                else: self._say(summary+"\nRemaining: "+", ".join(item["tag"] for item in progress["remaining"]))
            elif action=="answer" and self.engagement_id and len(rest)>=2:
                path=self.engagements.capture_questionnaire_answer(self.engagement_id,rest[0]," ".join(rest[1:]),"operator")
                progress=self.engagements.questionnaire_progress(self.engagement_id)
                self._say(f"Captured {rest[0].upper()} for review ({progress['answered']}/{progress['total']}): {path}\nAuthorization and engagement state were not changed.")
            elif action=="candidate" and self.engagement_id: self._say("Ask the AI to return CSTK_ENGAGEMENT_CANDIDATE followed by a JSON object. It will be recorded for review and cannot alter authorization.")
            else: raise BridgeError("usage: /engagement list | use ID | show | progress | next | answer TAG TEXT | candidate")
        except (BridgeError,OSError,KeyError,ValueError) as e: self._say(f"[red]Engagement error: {e}[/]")
    def _set_provider(self,args):
        if len(args)<3: self._say("Usage: /provider NAME URL MODEL [KEY_ENV]"); return
        p=ProviderConfig(args[0],args[1],args[2],args[3] if len(args)>3 else "")
        try: p.validate()
        except ProviderConfigError as e: self._say(f"[red]Provider rejected: {e}[/]"); return
        self._activate_provider(p,"configured")
    def _credential(self,args):
        env_name=args[0] if args else (self.provider.api_key_env if self.provider else "")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*",env_name):
            self._say("Usage: /credential KEY_ENV (for example /credential CSTK_AI_KEY)"); return
        self.push_screen(CredentialScreen(env_name),lambda value:self._credential_done(env_name,value))
    def _credential_done(self,env_name,value):
        if value:
            os.environ[env_name]=value; self._session_credentials.add(env_name)
            self._say(f"Credential loaded for this CSTK AI session: {env_name}. The value was not displayed or saved.")
        else: self._say("Credential entry cancelled.")
    def _activate_provider(self,provider,reason):
        previous=self.provider; changed=previous is not None and (previous.name,previous.base_url,previous.model)!=(provider.name,provider.base_url,provider.model)
        self.provider=provider; self.connection_state="READY"
        if changed:
            self.messages.clear(); self._say(f"[bold #ffaf00]AI SESSION CHANGED[/] {previous.name}/{previous.model} → {provider.name}/{provider.model}\nOutbound conversation context reset; the visible transcript remains on screen.")
        else: self._say(f"Provider {reason}: [bold]{provider.name}[/] • model [bold]{provider.model}[/]. No request sent yet.")
        self._panels()
    def _change_model(self,model):
        p=self.provider; old=p.model
        if model==old: self._say(f"Model remains {model}."); return
        self.provider=ProviderConfig(p.name,p.base_url,model,p.api_key_env,p.protocol,p.timeout_seconds)
        self.messages.clear(); self.connection_state="READY"; self._panels()
        self._say(f"[bold #ffaf00]AI MODEL CHANGED[/] {old} → {model}\nOutbound conversation context reset; the visible transcript remains on screen.")
    def _expand(self,text):
        engagement="[No active phase-2 engagement selected]"
        scope_context="[No validated operational scope; operator text is not authorization]"
        if self.engagements and self.engagement_id:
            try:
                context=self.engagements.ai_context(self.engagement_id)
                engagement="[CSTK active engagement context: "+json.dumps(context,sort_keys=True)+"]"
                scope_context="[Validated scope: "+json.dumps(context["scope"],sort_keys=True)+"]"
            except (BridgeError,OSError,KeyError,ValueError) as error: engagement=f"[Engagement context withheld: {error}]"
        vals={"@engagement":engagement,"@scope":scope_context,"@session":f"[Provider: {self.provider.name if self.provider else 'not set'}]","@privacy":"[Explicit context only; no autonomous tools]"}
        for k,v in vals.items(): text=text.replace(k,v)
        return text
    def _send(self,text):
        self._refresh_hud()
        if not self.provider: self._say("[red]Configure a provider with /provider first.[/]"); return
        self._say(f"[bold #00d7ff]YOU[/]  {text}"); self.messages.append(ChatMessage("user",self._expand(text)))
        try: request=prepare_chat_request(self.provider,self.messages)
        except (ProviderConfigError,ValueError) as e: self.messages.pop(); self._say(f"[red]Blocked: {e}[/]"); return
        self.connection_state="CONTACTING"; self._panels(); self._say("[#87afaf]Contacting the selected provider…[/]"); self._request(request)
    @work(thread=True,exclusive=True,group="provider")
    def _request(self,request):
        try: answer=send_prepared_request(request,self.provider.timeout_seconds)
        except ProviderTransportError as e: self.call_from_thread(self._failed,str(e)); return
        self.call_from_thread(self._answered,answer)
    def _failed(self,error):
        if self.messages and self.messages[-1].role=="user": self.messages.pop()
        self.connection_state="ERROR"; self._panels(); self._say(f"[red]Provider error: {error}[/]")
    def _answered(self,answer):
        self.connection_state="READY"; self._panels(); answer=answer or "Empty response"; self.messages.append(ChatMessage("assistant",answer)); self._say(f"[bold #5fff87]AI[/]  {answer}")
        marker="CSTK_ENGAGEMENT_CANDIDATE:"
        if self.engagements and self.engagement_id and marker in answer:
            try:
                payload=json.loads(answer.split(marker,1)[1].strip()); path=self.engagements.capture_ai_candidate(self.engagement_id,payload)
                self._say(f"[bold #ffaf00]Engagement candidate captured for review:[/] {path}. The active authorization record was not changed.")
            except (BridgeError,ValueError,TypeError): self._say("[red]AI engagement candidate was invalid and was ignored.[/]")
        marker="CSTK_QUESTIONNAIRE_ANSWER:"
        if self.engagements and self.engagement_id and marker in answer:
            try:
                payload=json.loads(answer.split(marker,1)[1].strip())
                path=self.engagements.capture_questionnaire_answer(self.engagement_id,payload["tag"],payload["answer"],"ai")
                progress=self.engagements.questionnaire_progress(self.engagement_id)
                self._say(f"[bold #ffaf00]Questionnaire answer captured for review:[/] {path} ({progress['answered']}/{progress['total']}). Authorization was not changed.")
            except (BridgeError,KeyError,ValueError,TypeError): self._say("[red]AI questionnaire answer was invalid and was ignored.[/]")
    def action_clear_chat(self): self.messages.clear(); self.query_one("#chat",RichLog).clear(); self._say("Conversation cleared; provider retained.")
    def action_help(self): self._command("/help")
    def action_palette(self): self.push_screen(Palette(),self._palette_done)
    def on_unmount(self):
        for env_name in self._session_credentials: os.environ.pop(env_name,None)
        self._session_credentials.clear()
    def _palette_done(self,cmd):
        field=self.query_one("#prompt",Input)
        if cmd: field.value=cmd; field.cursor_position=len(cmd)
        field.focus()

if __name__=="__main__": CSTKAnalystV2().run()
