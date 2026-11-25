"use client";import{J as u}from"./chunk-KV47LBTR.js";import{a as y,b as f}from"./chunk-YEAN2OM6.js";import{c as t}from"./chunk-OOJM4CTU.js";var e=t(y());var r=t(f()),P=`
.cc-crepe .milkdown {
  --crepe-color-background: var(--surface);
  --crepe-color-on-background: var(--ink);
  --crepe-color-surface: var(--bg-2);
  --crepe-color-surface-low: var(--bg-2);
  --crepe-color-on-surface: var(--ink);
  --crepe-color-on-surface-variant: var(--ink-2);
  --crepe-color-outline: var(--line-2);
  --crepe-color-primary: var(--brand);
  --crepe-color-secondary: var(--brand-soft);
  --crepe-color-on-secondary: var(--ink);
  --crepe-color-inverse: var(--ink);
  --crepe-color-on-inverse: var(--surface);
  --crepe-color-inline-code: var(--ink);
  --crepe-color-error: var(--block-fg);
  --crepe-color-hover: var(--bg-2);
  --crepe-color-selected: var(--brand-soft);
  --crepe-color-inline-area: var(--line);
  --crepe-font-title: inherit;
  --crepe-font-default: inherit;
  --crepe-font-code: var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace);
  --crepe-base-font-size: 14.5px;
  background: transparent;
  color: var(--ink);
  font-family: inherit;
  font-size: 14.5px;
  line-height: 1.65;
}
.cc-crepe .milkdown .ProseMirror {
  padding: 4px 2px;
  max-height: 62vh;
  overflow: auto;
}
.cc-crepe .milkdown .ProseMirror:focus-visible { outline: none; }
.cc-crepe .milkdown .ProseMirror h1,
.cc-crepe .milkdown .ProseMirror h2,
.cc-crepe .milkdown .ProseMirror h3,
.cc-crepe .milkdown .ProseMirror h4,
.cc-crepe .milkdown .ProseMirror h5,
.cc-crepe .milkdown .ProseMirror h6 { font-family: inherit; font-weight: 600; padding: 0; line-height: 1.3; }
.cc-crepe .milkdown .ProseMirror h1 { font-size: 22px; letter-spacing: -0.02em; margin: 24px 0 8px; }
.cc-crepe .milkdown .ProseMirror h2 { font-size: 17px; letter-spacing: -0.01em; margin: 20px 0 6px; }
.cc-crepe .milkdown .ProseMirror h3 { font-size: 15px; margin: 16px 0 4px; }
.cc-crepe .milkdown .ProseMirror h4,
.cc-crepe .milkdown .ProseMirror h5,
.cc-crepe .milkdown .ProseMirror h6 { font-size: 14.5px; margin: 12px 0 4px; }
.cc-crepe .milkdown .ProseMirror > :first-child { margin-top: 0; }
.cc-crepe .milkdown .ProseMirror p { line-height: 1.65; padding: 3px 0; }
.cc-crepe .milkdown .ProseMirror a { color: var(--brand-ink); }
.cc-crepe .milkdown .ProseMirror code { font-family: var(--crepe-font-code); font-size: 13px; background: var(--bg-2); color: var(--ink); }
.cc-crepe .milkdown .ProseMirror blockquote::before { background: var(--line-2); }
.cc-crepe .milkdown .ProseMirror blockquote { color: var(--ink-2); padding-left: 14px; }
.cc-crepe .milkdown .ProseMirror hr { background-color: var(--line); }
.cc-crepe .milkdown table td, .cc-crepe .milkdown table th { border-color: var(--line); }
.cc-crepe .milkdown table th { background: var(--bg-2); font-weight: 600; }
.cc-crepe .milkdown .milkdown-code-block {
  margin: 12px 0;
  padding: 10px 14px;
  border: 1px solid var(--line);
  border-radius: 10px;
  background: var(--bg-2);
}
.cc-crepe .milkdown .milkdown-code-block .cm-editor,
.cc-crepe .milkdown .milkdown-code-block .cm-gutters { background: transparent; }
.cc-crepe .milkdown .milkdown-code-block .cm-gutters { display: none; }
.cc-crepe .milkdown .milkdown-code-block .cm-content,
.cc-crepe .milkdown .milkdown-code-block .cm-line { font-family: var(--crepe-font-code); font-size: 13px; line-height: 1.55; color: var(--ink); }
.cc-crepe .milkdown .milkdown-code-block .cm-activeLine { background: transparent; }
.cc-crepe .milkdown .milkdown-code-block .cm-content * { color: inherit !important; }
.cc-crepe .milkdown .milkdown-code-block .tools { position: absolute; top: 4px; right: 6px; margin: 0; z-index: 1; }
`;function T({value:w,onChange:a,onReady:l}){let p=(0,e.useRef)(null),d=(0,e.useRef)(a);d.current=a;let s=(0,e.useRef)(l);s.current=l;let b=(0,e.useRef)(w),[i,v]=(0,e.useState)(!1),[x,g]=(0,e.useState)(!1);return(0,e.useEffect)(()=>{let m=p.current;if(!m)return;let k=null,c=!1;return(async()=>{try{let{Crepe:n}=await import("./chunk-CBDCHG3P.js");if(c)return;let o=new n({root:m,defaultValue:b.current});if(o.on(h=>{h.markdownUpdated((z,M)=>d.current(M))}),await o.create(),c){o.destroy();return}k=o,s.current?.(o.getMarkdown()),v(!0)}catch(n){console.error("the markdown editor could not start",n),c||g(!0)}})(),()=>{c=!0,k?.destroy()}},[]),x?(0,r.jsx)("p",{className:"text-[13px] text-block","data-testid":"files-markdown-editor-failed",children:"Couldn\u2019t open the rich editor. Switch to Source to edit the Markdown."}):(0,r.jsxs)("div",{className:"cc-crepe","data-testid":"files-markdown-editor","data-ready":i?"1":"0",children:[(0,r.jsx)("style",{children:P}),i?null:(0,r.jsxs)("div",{className:"flex items-center gap-2 py-6 text-[13px] text-ink-2",children:[(0,r.jsx)(u,{className:"h-3.5 w-3.5 animate-spin"}),"Opening the editor\u2026"]}),(0,r.jsx)("div",{ref:p,className:i?void 0:"hidden"})]})}export{T as MarkdownEditor};
