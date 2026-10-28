"use client";import{x as u}from"./chunk-K3VUNMVL.js";import{a as M,b as x}from"./chunk-XDZRW5EK.js";import{c as n}from"./chunk-OOJM4CTU.js";var e=n(M());var r=n(x()),N=`
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
.cc-crepe .milkdown table td, .cc-crepe .milkdown table th { border-color: var(--line); }`;function H({value:k,onChange:a,onReady:s}){let p=(0,e.useRef)(null),l=(0,e.useRef)(a);l.current=a;let d=(0,e.useRef)(s);d.current=s;let w=(0,e.useRef)(k),[t,v]=(0,e.useState)(!1),[b,h]=(0,e.useState)(!1);return(0,e.useEffect)(()=>{let f=p.current;if(!f)return;let m=null,c=!1;return(async()=>{try{let{Crepe:i}=await import("./chunk-MWK7U2K7.js");if(c)return;let o=new i({root:f,defaultValue:w.current});if(o.on(g=>{g.markdownUpdated((C,y)=>l.current(y))}),await o.create(),c){o.destroy();return}m=o,d.current?.(o.getMarkdown()),v(!0)}catch(i){console.error("the markdown editor could not start",i),c||h(!0)}})(),()=>{c=!0,m?.destroy()}},[]),b?(0,r.jsx)("p",{className:"text-[13px] text-block","data-testid":"files-markdown-editor-failed",children:"Couldn\u2019t open the rich editor. Switch to Source to edit the Markdown."}):(0,r.jsxs)("div",{className:"cc-crepe","data-testid":"files-markdown-editor","data-ready":t?"1":"0",children:[(0,r.jsx)("style",{children:N}),t?null:(0,r.jsxs)("div",{className:"flex items-center gap-2 py-6 text-[13px] text-ink-2",children:[(0,r.jsx)(u,{className:"h-3.5 w-3.5 animate-spin"}),"Opening the editor\u2026"]}),(0,r.jsx)("div",{ref:p,className:t?void 0:"hidden"})]})}export{H as MarkdownEditor};
