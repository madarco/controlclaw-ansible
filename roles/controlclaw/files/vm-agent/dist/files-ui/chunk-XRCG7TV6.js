"use client";import{w as u}from"./chunk-XPXALLGA.js";import{a as N,b as x}from"./chunk-XDZRW5EK.js";import{c as a}from"./chunk-OOJM4CTU.js";var e=a(N());var r=a(x()),M=`
.cc-crepe { --crepe-color-background: transparent; }
.cc-crepe .milkdown {
  background: transparent;
  color: var(--ink);
  font-size: 13.5px;
  line-height: 1.7;
}
.cc-crepe .milkdown .ProseMirror {
  padding: 4px 2px;
  max-height: 52vh;
  overflow: auto;
}
.cc-crepe .milkdown .ProseMirror:focus-visible { outline: none; }
.cc-crepe .milkdown pre, .cc-crepe .milkdown code { font-family: var(--font-mono, ui-monospace, monospace); }
.cc-crepe .milkdown blockquote { border-left: 2px solid var(--line-2); padding-left: 12px; color: var(--ink-2); }
.cc-crepe .milkdown hr { border-color: var(--line); }
.cc-crepe .milkdown table td, .cc-crepe .milkdown table th { border-color: var(--line); }`;function H({value:k,onChange:n,onReady:s}){let l=(0,e.useRef)(null),p=(0,e.useRef)(n);p.current=n;let d=(0,e.useRef)(s);d.current=s;let w=(0,e.useRef)(k),[t,v]=(0,e.useState)(!1),[b,h]=(0,e.useState)(!1);return(0,e.useEffect)(()=>{let m=l.current;if(!m)return;let f=null,c=!1;return(async()=>{try{let{Crepe:i}=await import("./chunk-MWK7U2K7.js");if(c)return;let o=new i({root:m,defaultValue:w.current});if(o.on(g=>{g.markdownUpdated((S,y)=>p.current(y))}),await o.create(),c){o.destroy();return}f=o,d.current?.(o.getMarkdown()),v(!0)}catch(i){console.error("the markdown editor could not start",i),c||h(!0)}})(),()=>{c=!0,f?.destroy()}},[]),b?(0,r.jsx)("p",{className:"text-[13px] text-block","data-testid":"files-markdown-editor-failed",children:"The rich editor could not start. Switch to Source to edit the markdown directly."}):(0,r.jsxs)("div",{className:"cc-crepe","data-testid":"files-markdown-editor","data-ready":t?"1":"0",children:[(0,r.jsx)("style",{children:M}),t?null:(0,r.jsxs)("div",{className:"flex items-center gap-2 py-6 text-[13px] text-ink-2",children:[(0,r.jsx)(u,{className:"h-3.5 w-3.5 animate-spin"}),"Opening the editor\u2026"]}),(0,r.jsx)("div",{ref:l,className:t?void 0:"hidden"})]})}export{H as MarkdownEditor};
