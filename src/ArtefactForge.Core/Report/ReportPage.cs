namespace ArtefactForge.Core.Report;

/// <summary>
/// The report page's styles and shared script. Everything is inline and uses system fonts, as the
/// report must open on an offline analysis machine. Light and dark follow the viewer's system.
/// </summary>
internal static class ReportPage
{
    public const string Css = """
        :root{--bg:#f4f5f7;--paper:#fff;--line:#e2e4e8;--fg:#1a1d21;--muted:#626872;--accent:#2b6fd6;--accent-soft:#e3ecfa;
          --crit:#b42318;--crit-bg:#fde7e4;--high:#c2510c;--high-bg:#fdeee2;--med:#8a6700;--med-bg:#fbf3d6;--low:#4b6b8a;--low-bg:#e6eef5;
          --ok:#2e7d4f;--ok-bg:#e1f2e8;--mark:#ffe08a;--mark-fg:#1a1d21;
          --ui:"Segoe UI Variable Text","Segoe UI",system-ui,-apple-system,sans-serif;
          --mono:"Cascadia Mono",Consolas,ui-monospace,monospace;color-scheme:light}
        @media (prefers-color-scheme:dark){:root{
          --bg:#121417;--paper:#1b1e22;--line:#2e3238;--fg:#e8eaed;--muted:#9aa1ab;--accent:#5b9cf6;--accent-soft:#1d2d47;
          --crit:#f98b80;--crit-bg:#3d1714;--high:#f5a565;--high-bg:#3a2210;--med:#e6c24d;--med-bg:#332a0d;--low:#9db8d4;--low-bg:#1c2836;
          --ok:#6fcf97;--ok-bg:#16301f;--mark:#6b5310;--mark-fg:#fff3c4;color-scheme:dark}}
        *{box-sizing:border-box}
        html{scroll-behavior:smooth}
        @media (prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
        body{margin:0;background:var(--bg);color:var(--fg);font-family:var(--ui);font-size:14px;line-height:1.45}
        .page{max-width:1400px;margin:0 auto;padding:0 16px;display:grid;grid-template-columns:200px minmax(0,1fr);gap:24px}
        nav{position:sticky;top:0;align-self:start;padding-block:24px;display:flex;flex-direction:column;gap:2px}
        nav .brand{font-weight:600;font-size:13px;margin-bottom:12px;color:var(--muted);letter-spacing:.04em;text-transform:uppercase}
        nav a{color:var(--fg);text-decoration:none;padding:6px 10px;border-radius:5px;display:flex;justify-content:space-between;gap:8px}
        nav a:hover{background:var(--paper)}
        nav a.on{background:var(--accent-soft);color:var(--accent)}
        nav a .c{color:var(--muted);font-variant-numeric:tabular-nums;font-size:12px}
        main{padding-block:24px 60px;display:flex;flex-direction:column;gap:28px;min-width:0}
        @media (max-width:820px){.page{grid-template-columns:minmax(0,1fr);gap:0}
          nav{flex-direction:row;overflow-x:auto;background:var(--bg);padding-block:10px;z-index:2;border-bottom:1px solid var(--line)}
          nav .brand{display:none} nav a{white-space:nowrap}}
        header.case{display:flex;flex-direction:column;gap:10px}
        h1{font-size:24px;font-weight:600;margin:0}
        h2{font-size:17px;font-weight:600;margin:0}
        h3{font-size:14px;font-weight:600;margin:0}
        p{margin:0}
        .meta{display:flex;flex-wrap:wrap;gap:6px 18px;color:var(--muted);font-size:13px;align-items:center}
        .meta b{color:var(--fg);font-weight:500}
        .live{display:inline-flex;align-items:center;gap:6px;font-size:12px;border:1px solid var(--line);border-radius:12px;padding:2px 10px;background:var(--paper)}
        .live i{width:7px;height:7px;border-radius:50%;background:var(--ok)}
        .live.snap i{background:var(--muted)}
        section{display:flex;flex-direction:column;gap:12px;scroll-margin-top:16px}
        .sec-head{display:flex;flex-wrap:wrap;align-items:baseline;gap:6px 14px}
        .src,.small{font-size:12px;color:var(--muted)}
        .muted{color:var(--muted)}
        .mono{font-family:var(--mono);font-size:12.5px}
        .box{background:var(--paper);border:1px solid var(--line);border-radius:8px}
        .empty{padding:14px;color:var(--muted)}
        .findings{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
        .finding{background:var(--paper);border:1px solid var(--line);border-left:4px solid var(--line);border-radius:6px;padding:12px 14px;display:flex;flex-direction:column;gap:4px;text-decoration:none;color:var(--fg)}
        .finding:hover{border-color:var(--muted)}
        .finding.crit{border-left-color:var(--crit)}.finding.high{border-left-color:var(--high)}.finding.med{border-left-color:var(--med)}
        .finding .big{font-size:22px;font-weight:600;font-variant-numeric:tabular-nums;overflow-wrap:anywhere}
        .finding .big.long{font-size:17px;font-family:var(--mono)}
        .finding .lbl{font-size:13px}
        .finding .sub{font-size:12px;color:var(--muted)}
        .tbl{overflow-x:auto}
        table{border-collapse:collapse;width:100%;font-size:13px;font-variant-numeric:tabular-nums}
        th{text-align:left;font-weight:500;color:var(--muted);padding:8px 12px;border-bottom:1px solid var(--line);white-space:nowrap}
        td{padding:8px 12px;border-bottom:1px solid var(--line);white-space:nowrap;vertical-align:top}
        tbody tr:last-child td{border-bottom:0}
        td.wrap{white-space:normal;min-width:260px;overflow-wrap:anywhere}
        .pill{display:inline-block;border-radius:10px;padding:1px 9px;font-size:12px;white-space:nowrap}
        .p-crit{background:var(--crit-bg);color:var(--crit)}.p-high{background:var(--high-bg);color:var(--high)}
        .p-med{background:var(--med-bg);color:var(--med)}.p-low{background:var(--low-bg);color:var(--low)}
        .p-ok{background:var(--ok-bg);color:var(--ok)}.p-plain{background:var(--bg);color:var(--muted);border:1px solid var(--line)}
        .stack{display:flex;height:10px;border-radius:5px;overflow:hidden;min-width:160px;background:var(--bg)}
        .stack span{display:block;height:100%}
        .s-crit{background:var(--crit)}.s-high{background:var(--high)}.s-med{background:var(--med)}.s-low{background:var(--low)}
        .legend{display:flex;flex-wrap:wrap;gap:12px;font-size:12px;color:var(--muted)}
        .legend span{display:inline-flex;align-items:center;gap:5px}
        .legend i{width:10px;height:10px;border-radius:2px;display:inline-block}
        .ioc{border-bottom:1px solid var(--line)}
        .ioc:last-child{border-bottom:0}
        summary{list-style:none;cursor:pointer}
        summary::-webkit-details-marker{display:none}
        .ioc summary{display:flex;flex-wrap:wrap;align-items:center;gap:8px 14px;padding:10px 14px}
        .ioc summary::before,.trace>summary::before{content:"\203A";color:var(--muted);transition:transform .15s;display:inline-block;width:10px}
        .ioc[open] summary::before,.trace[open]>summary::before{transform:rotate(90deg)}
        .ioc summary .v{font-family:var(--mono);font-weight:600;overflow-wrap:anywhere}
        .ioc summary .t{font-size:12px;color:var(--muted);min-width:70px}
        .ioc summary .n{font-size:12px;color:var(--muted)}
        .ioc summary .r{margin-left:auto;display:flex;gap:6px;flex-wrap:wrap}
        .ioc .inner{padding:0 14px 12px 38px}
        .ioc .inner p{padding:6px 12px}
        mark{background:var(--mark);color:var(--mark-fg);border-radius:2px;padding:0 1px}
        .copy{font:inherit;font-size:11px;color:var(--muted);background:transparent;border:1px solid var(--line);border-radius:4px;padding:0 6px;cursor:pointer}
        .copy:hover{color:var(--fg);border-color:var(--muted)}
        button:focus-visible,a:focus-visible,input:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
        .trace-meta{display:flex;flex-wrap:wrap;gap:8px 16px;padding:12px 14px;align-items:center}
        .trace[open]>.trace-meta{border-bottom:1px solid var(--line)}
        .chain-wrap{overflow-x:auto;padding:16px 14px}
        .chain{display:flex;align-items:center;min-width:min-content}
        .node{border:1px solid var(--line);border-radius:6px;padding:8px 12px;background:var(--bg);display:flex;flex-direction:column;gap:2px;min-width:130px}
        .node small{color:var(--muted);font-size:12px}
        .node.ext{border-color:var(--crit);background:var(--crit-bg)}.node.ext b{color:var(--crit)}
        .node.collect{border-color:var(--med);background:var(--med-bg)}
        .node.start{border:2px solid var(--accent)}
        .arrow{flex:1;min-width:120px;display:flex;flex-direction:column;align-items:center;gap:4px;padding:0 6px;font-size:11.5px;color:var(--muted);text-align:center}
        .arrow .ln{width:100%;height:2px;background:var(--muted);position:relative}
        .arrow .ln::after{content:"";position:absolute;right:-1px;top:-4px;border-left:8px solid var(--muted);border-top:5px solid transparent;border-bottom:5px solid transparent}
        .flags{display:flex;flex-direction:column;gap:6px;padding:12px 14px;border-top:1px solid var(--line);font-size:13px}
        .box.flags{border-top:1px solid var(--line)}
        .lookup{display:flex;flex-wrap:wrap;gap:8px;align-items:center;padding:12px 14px;border-bottom:1px solid var(--line)}
        .lookup input{font:inherit;font-size:13px;color:var(--fg);background:var(--bg);border:1px solid var(--line);border-radius:5px;padding:6px 8px;min-width:0;flex:0 1 220px}
        #ipMore{padding:8px 14px}
        footer{color:var(--muted);font-size:12px;border-top:1px solid var(--line);padding-top:14px;display:flex;flex-direction:column;gap:4px}
        @media print{nav{display:none}.page{display:block}.tbl{overflow:visible}}
        """;

    /// <summary>Copy buttons and the nav's current-section marker. Sections add their own after this.</summary>
    public const string Script = """
        document.addEventListener("click",e=>{const b=e.target.closest(".copy");if(!b)return;e.preventDefault();e.stopPropagation();
          const v=b.dataset.copy,done=t=>{b.textContent=t;setTimeout(()=>b.textContent="Copy",1200)};
          try{navigator.clipboard.writeText(v).then(()=>done("Copied"),()=>done("Select to copy"))}catch(_){done("Select to copy")}});
        (function(){const links=[...document.querySelectorAll("#nav a")],secs=links.map(a=>document.getElementById(a.getAttribute("href").slice(1)));
          function on(){let cur=0;secs.forEach((s,i)=>{if(s&&s.getBoundingClientRect().top<120)cur=i});links.forEach((a,i)=>a.classList.toggle("on",i===cur))}
          addEventListener("scroll",on,{passive:true});on();})();
        """;
}
