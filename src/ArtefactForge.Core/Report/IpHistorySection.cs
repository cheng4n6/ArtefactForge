using System.Text;
using System.Text.Json;
using ArtefactForge.Core.Windows;
using static ArtefactForge.Core.Report.Html;

namespace ArtefactForge.Core.Report;

/// <summary>
/// The case IP history (IpHistory.csv at the case root), with a "who had this address at this
/// time" lookup that runs in the page. The rows are embedded as data, not as a table, so a large
/// history stays quick to open; the page shows the rows that match the lookup.
/// </summary>
internal sealed class IpHistorySection : ICaseReportSection
{
    // A domain's history can run to tens of thousands of rows; past this the page gets slow to open.
    private const int MaxRows = 50_000;

    public ReportSection Build(CaseReportContext context)
    {
        var path = Path.Combine(context.CaseDirectory, IpHistory.FileName);
        if (!File.Exists(path))
            return new ReportSection
            {
                Id = "ips", Title = "IP history",
                Source = "IpHistory.csv, built when a domain controller or DHCP server is processed",
                Body = Empty("No IP history in this case: it is built from a domain controller's Kerberos events or a DHCP server's logs, and none has been processed.")
            };

        var rows = IpHistoryRecord.Read(path);
        var first = rows.Min(r => r.FirstSeenUtc);
        var last = rows.Max(r => r.LastSeenUtc);
        var sources = string.Join(", ", rows.Select(r => r.Source).Where(s => s.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase));
        var covers = first is null ? "" : $" covering {Day(first)} to {Day(last)}";

        var data = rows.Take(MaxRows).Select(r => new[]
        {
            r.IpAddress, r.HostName, r.Account, r.MacAddress, Time(r.FirstSeenUtc), Time(r.LastSeenUtc), r.Source,
            r.EventCount?.ToString() ?? ""
        });
        // The default encoder escapes <, > and &, so the data cannot close the script element.
        var json = JsonSerializer.Serialize(data);

        var body = new StringBuilder()
            .Append("<div class=\"box\"><form class=\"lookup\" id=\"ipLookup\" autocomplete=\"off\">")
            .Append("<label for=\"ipq\">Who had</label><input id=\"ipq\" class=\"mono\" placeholder=\"IP address or host\">")
            .Append("<label for=\"ipt\">at</label><input id=\"ipt\" class=\"mono\" placeholder=\"yyyy-MM-dd HH:mm\" style=\"flex-basis:170px\">")
            .Append("<span class=\"answer\" id=\"ipAnswer\" aria-live=\"polite\"></span></form>")
            .Append("<noscript><p class=\"empty\">The lookup needs scripts, which this browser has turned off. The full history is in IpHistory.csv.</p></noscript>")
            .Append("<div class=\"tbl\"><table><thead><tr><th>IP</th><th>Host</th><th>Account</th><th>MAC</th><th>First seen (UTC)</th>")
            .Append("<th>Last seen (UTC)</th><th>Source</th><th>Events</th></tr></thead><tbody id=\"ipRows\"></tbody></table></div>")
            .Append("<p class=\"muted small\" id=\"ipMore\"></p></div>");
        if (rows.Count > MaxRows)
            body.Append($"<p class=\"muted\">The first {N(MaxRows)} of {N(rows.Count)} rows are in this report. Every row is in IpHistory.csv.</p>");

        return new ReportSection
        {
            Id = "ips", Title = "IP history", Count = N(rows.Count),
            Source = $"IpHistory.csv from {(sources.Length > 0 ? sources : "no sources")}{covers}",
            Body = body.ToString(),
            Script = "const ipData=" + json + ";\n" + Script
        };
    }

    // Times compare as text: every one is yyyy-MM-dd HH:mm:ss. A row with no times (SystemInfo,
    // the host's own address at collection) answers a lookup with no time given.
    private const string Script = """
        (function(){
          const q=document.getElementById("ipq"),t=document.getElementById("ipt"),rows=document.getElementById("ipRows");
          const answer=document.getElementById("ipAnswer"),more=document.getElementById("ipMore");
          const esc=s=>String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
          const limit=500;
          function show(){
            const v=q.value.trim().toLowerCase(),when=t.value.trim().replace("T"," ");
            const match=ipData.filter(r=>!v||r[0].toLowerCase().includes(v)||r[1].toLowerCase().includes(v)||r[2].toLowerCase().includes(v));
            rows.innerHTML=match.slice(0,limit).map(r=>`<tr><td class="mono">${esc(r[0])}</td><td><b>${esc(r[1])}</b></td><td>${esc(r[2])}</td><td class="mono muted">${esc(r[3])}</td><td class="mono">${esc(r[4])}</td><td class="mono">${esc(r[5])}</td><td class="muted">${esc(r[6])}</td><td>${esc(r[7])}</td></tr>`).join("")
              ||`<tr><td colspan="8" class="muted">No rows match.</td></tr>`;
            more.textContent=match.length>limit?`Showing ${limit} of ${match.length} matching rows. Narrow the search to see the rest.`:"";
            const exact=ipData.filter(r=>r[0].toLowerCase()===v);
            if(!exact.length||!when){answer.innerHTML="";return;}
            const held=exact.filter(r=>r[4]&&r[5]&&when>=r[4].slice(0,when.length)&&when<=r[5].slice(0,when.length));
            const names=[...new Set(held.map(r=>r[1]||r[2]).filter(n=>n))];
            const others=[...new Set(exact.map(r=>r[1]||r[2]).filter(n=>n&&!names.includes(n)))];
            answer.innerHTML=names.length
              ?`<b>${names.map(esc).join(", ")}</b>`+(names.length>1?` <span class="pill p-med">More than one host</span>`:"")+(others.length?` <span class="muted">Also held by ${others.map(esc).join(", ")} at other times</span>`:"")
              :`<span class="muted">No host is recorded with that address at that time</span>`;
          }
          document.getElementById("ipLookup").addEventListener("input",show);
          document.getElementById("ipLookup").addEventListener("submit",e=>{e.preventDefault();show();});
          show();
        })();
        """;
}
