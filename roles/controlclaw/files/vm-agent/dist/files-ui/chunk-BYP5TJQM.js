"use client";import{a as M,b as B,c as K,d as R,e as D}from"./chunk-SSC34VFQ.js";import{a as T,b as p}from"./chunk-XDZRW5EK.js";import{Ha as S,M as o,N as b,P as y,R as k,S as C,Ya as L,Za as E,ab as H,ba as w,ca as x,fa as c,t as h,ua as N,y as v}from"./chunk-GLGK7KJV.js";import{c as n}from"./chunk-OOJM4CTU.js";var t=n(T());var r=n(p()),W=`
.cc-cm {
  --cc-cm-comment: #6a737d;
  --cc-cm-keyword: #cf222e;
  --cc-cm-string: #0a3069;
  --cc-cm-number: #0550ae;
  --cc-cm-name: #953800;
  --cc-cm-function: #8250df;
  --cc-cm-type: #116329;
  --cc-cm-invalid: #82071e;
  --cc-cm-selection: rgba(84, 110, 255, 0.18);
}
.dark .cc-cm {
  --cc-cm-comment: #8b949e;
  --cc-cm-keyword: #ff7b72;
  --cc-cm-string: #a5d6ff;
  --cc-cm-number: #79c0ff;
  --cc-cm-name: #ffa657;
  --cc-cm-function: #d2a8ff;
  --cc-cm-type: #7ee787;
  --cc-cm-invalid: #ffa198;
  --cc-cm-selection: rgba(140, 160, 255, 0.28);
}`,A=L.define([{tag:[c.comment,c.lineComment,c.blockComment],color:"var(--cc-cm-comment)",fontStyle:"italic"},{tag:[c.keyword,c.modifier,c.controlKeyword,c.operatorKeyword],color:"var(--cc-cm-keyword)"},{tag:[c.string,c.special(c.string),c.regexp],color:"var(--cc-cm-string)"},{tag:[c.number,c.bool,c.null,c.atom],color:"var(--cc-cm-number)"},{tag:[c.variableName,c.propertyName,c.attributeName],color:"var(--cc-cm-name)"},{tag:[c.function(c.variableName),c.function(c.propertyName),c.labelName],color:"var(--cc-cm-function)"},{tag:[c.typeName,c.className,c.tagName,c.heading],color:"var(--cc-cm-type)"},{tag:[c.link,c.url],color:"var(--cc-cm-function)",textDecoration:"underline"},{tag:c.strong,fontWeight:"600"},{tag:c.emphasis,fontStyle:"italic"},{tag:c.invalid,color:"var(--cc-cm-invalid)"}]),G=o.theme({"&":{color:"var(--ink)",backgroundColor:"transparent",fontSize:"12.5px"},".cm-content":{fontFamily:"var(--font-mono, ui-monospace, SFMono-Regular, Menlo, monospace)",padding:"8px 0",caretColor:"var(--ink)"},".cm-scroller":{lineHeight:"1.6",overflow:"auto",maxHeight:"52vh"},"&.cm-focused":{outline:"none"},".cm-gutters":{backgroundColor:"transparent",color:"var(--ink-2)",border:"none",borderRight:"1px solid var(--line)",paddingRight:"6px"},".cm-activeLine":{backgroundColor:"var(--bg-2)"},".cm-activeLineGutter":{backgroundColor:"transparent",color:"var(--ink)"},".cm-cursor, .cm-dropCursor":{borderLeftColor:"var(--ink)"},"&.cm-focused .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection":{backgroundColor:"var(--cc-cm-selection)"},".cm-matchingBracket, .cm-nonmatchingBracket":{backgroundColor:"var(--brand-soft)",outline:"1px solid var(--brand-border)"}});function J({value:F,fileName:a,onChange:i}){let m=(0,t.useRef)(null),l=(0,t.useRef)(i);return l.current=i,(0,t.useEffect)(()=>{let s=m.current;if(!s)return;let g=new h,d=new o({parent:s,state:v.create({doc:F,extensions:[w(),x(),C(),k(),y(),B(),S(),H(),E(A),g.of([]),b.of([...R,...K,D]),o.lineWrapping,G,o.updateListener.of(e=>{e.docChanged&&l.current(e.state.doc.toString())})]})}),f=!1,u=N.matchFilename(M,a);return u&&u.load().then(e=>{f||d.dispatch({effects:g.reconfigure(e)})}).catch(e=>{console.warn("no CodeMirror grammar for this file",e)}),()=>{f=!0,d.destroy()}},[a]),(0,r.jsxs)("div",{className:"cc-cm","data-testid":"files-code-editor",children:[(0,r.jsx)("style",{children:W}),(0,r.jsx)("div",{ref:m})]})}export{J as CodeEditor};
