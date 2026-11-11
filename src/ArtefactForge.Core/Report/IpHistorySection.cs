using System.Text;
using System.Text.Json;
using ArtefactForge.Core.Windows;
using static ArtefactForge.Core.Report.Html;

namespace ArtefactForge.Core.Report;

/// <summary>
/// The case IP history (IpHistory.csv at the case root), with a "who had this address at this
/// time" lookup that runs in the page. The rows are embedded as data, not as a table, so a large
/// history stays quick to open; the page shows the rows that match the lookup. An address shown
/// anywhere else in the report links here and fills in the lookup.
///
/// Below it, the case's known addresses: the labels the report puts beside addresses, from
/// KnownAddresses.csv and the system summaries.
/// </summary>
internal sealed class IpHistorySection : ICaseReportSection
{
    // A domain's history can run to tens of thousands of rows; past this the page gets slow to open.
    private const int MaxRows = 50_000;

    private const string Source = "IpHistory.csv, built when a domain controller or DHCP server is processed";

    public ReportSection Build(CaseReportContext context)
    {
        var known = KnownAddressesBox(context, out var knownFindings);
        if (context.IpHistory is not { } rows)
            return new ReportSection
            {
                Id = "ips", Title = "IP history", Source = Source,
                Body = Empty("No IP history in this case: it is built from a domain controller's Kerberos events or a DHCP server's logs, and none has been processed.")
                       + known,
                Findings = knownFindings
            };

        var first = rows.Min(r => r.FirstSeenUtc);
        var last = rows.Max(r => r.LastSeenUtc);
        var sources = string.Join(", ", rows.Select(r => r.Source).Where(s => s.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase));
        var covers = first is null ? "" : $" covering {Day(first)} to {Day(last)}";

        var data = rows.Take(MaxRows).Select(r =>
        {
            var label = context.KnownAddresses.For(r.IpAddress);
            return new[]
            {
                r.IpAddress, r.HostName, r.Account, r.MacAddress, Time(r.FirstSeenUtc), Time(r.LastSeenUtc), r.Source,
                r.EventCount?.ToString() ?? "", label?.Label ?? "",
                label is null ? "" : (label.Note.Length > 0 ? label.Note + ". " : "") + "From " + label.From
            };
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
        body.Append(known);

        return new ReportSection
        {
            Id = "ips", Title = "IP history", Count = N(rows.Count),
            Source = $"IpHistory.csv from {(sources.Length > 0 ? sources : "no sources")}{covers}",
            Body = body.ToString(),
            Script = "const ipData=" + json + ";\n" + Script,
            Findings = knownFindings
        };
    }

    /// <summary>
    /// The labels the report puts beside addresses, and any line of KnownAddresses.csv that could
    /// not be read, which is also raised so a typo does not leave an address quietly unlabelled.
    /// </summary>
    private static string KnownAddressesBox(CaseReportContext context, out List<ReportFinding> findings)
    {
        findings = [];
        var known = context.KnownAddresses;
        var html = new StringBuilder("<h3 id=\"known\" style=\"margin-top:8px\">Known addresses</h3>");
        if (known.Problems.Count > 0)
        {
            findings.Add(new ReportFinding(FindingLevel.Medium, N(known.Problems.Count),
                $"{Plural(known.Problems.Count, "Line", "Lines")} of {KnownAddresses.FileName} not read",
                known.Problems[0] + (known.Problems.Count > 1 ? $"; and {known.Problems.Count - 1} more" : ""), "ips"));
            html.Append("<div class=\"box flags\">")
                .Append(string.Concat(known.Problems.Select(p => $"<div>{Pill("Not read", "med")} {E(p)}</div>")))
                .Append("</div>");
        }

        var how = $"Add your own in {KnownAddresses.FileName} in the case folder (Address, Label, Note; an IP or a CIDR range "
                  + "such as 10.8.0.0/16), or with Known addresses in the app. The most specific match is shown.";
        if (known.Entries.Count == 0)
            return html.Append(Empty("No known addresses yet. Domain controllers, DNS servers and gateways from the system summaries are labelled here once there are any. " + how))
                       .ToString();

        html.Append("<div class=\"box tbl\"><table><thead><tr><th>Address</th><th>Label</th><th>Note</th><th>From</th></tr></thead><tbody>");
        foreach (var (address, label) in known.Entries)
            html.Append("<tr>")
                .Append($"<td class=\"mono\">{E(address)}</td>")
                .Append($"<td>{Pill(label.Label, "tag")}</td>")
                .Append($"<td class=\"wrap\">{E(label.Note)}</td>")
                .Append($"<td class=\"muted\">{E(label.From)}</td>")
                .Append("</tr>");
        html.Append("</tbody></table></div>")
            .Append($"<p class=\"muted small\">{E(how)}</p>");
        return html.ToString();
    }

    // Times compare as text: every one is yyyy-MM-dd HH:mm:ss. A row with no times (SystemInfo,
    // the host's own address at collection) answers a lookup with no time given. An address link
    // elsewhere in the report calls ipLookup, which shows that address's rows only; typing searches
    // for any row containing the text again.
    private const string Script = """
        (function(){
          const q=document.getElementById("ipq"),t=document.getElementById("ipt"),rows=document.getElementById("ipRows");
          const answer=document.getElementById("ipAnswer"),more=document.getElementById("ipMore");
          const esc=s=>String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
          const limit=500;
          let exact=false;
          function show(){
            const v=q.value.trim().toLowerCase(),when=t.value.trim().replace("T"," ");
            const match=ipData.filter(r=>!v||(exact?r[0].toLowerCase()===v:r[0].toLowerCase().includes(v)||r[1].toLowerCase().includes(v)||r[2].toLowerCase().includes(v)));
            rows.innerHTML=match.slice(0,limit).map(r=>`<tr><td class="mono">${esc(r[0])}${r[8]?` <span class="pill p-tag" title="${esc(r[9])}">${esc(r[8])}</span>`:""}</td><td><b>${esc(r[1])}</b></td><td>${esc(r[2])}</td><td class="mono muted">${esc(r[3])}</td><td class="mono">${esc(r[4])}</td><td class="mono">${esc(r[5])}</td><td class="muted">${esc(r[6])}</td><td>${esc(r[7])}</td></tr>`).join("")
              ||`<tr><td colspan="8" class="muted">No rows match.</td></tr>`;
            more.textContent=match.length>limit?`Showing ${limit} of ${match.length} matching rows. Narrow the search to see the rest.`:"";
            const exactRows=ipData.filter(r=>r[0].toLowerCase()===v);
            if(!exactRows.length||!when){answer.innerHTML="";return;}
            const held=exactRows.filter(r=>r[4]&&r[5]&&when>=r[4].slice(0,when.length)&&when<=r[5].slice(0,when.length));
            const names=[...new Set(held.map(r=>r[1]||r[2]).filter(n=>n))];
            const others=[...new Set(exactRows.map(r=>r[1]||r[2]).filter(n=>n&&!names.includes(n)))];
            answer.innerHTML=names.length
              ?`<b>${names.map(esc).join(", ")}</b>`+(names.length>1?` <span class="pill p-med">More than one host</span>`:"")+(others.length?` <span class="muted">Also held by ${others.map(esc).join(", ")} at other times</span>`:"")
              :`<span class="muted">No host is recorded with that address at that time</span>`;
          }
          q.addEventListener("input",()=>{exact=false;});
          document.getElementById("ipLookup").addEventListener("input",show);
          document.getElementById("ipLookup").addEventListener("submit",e=>{e.preventDefault();show();});
          window.ipLookup=ip=>{q.value=ip;exact=true;show();document.getElementById("ips").scrollIntoView();q.focus({preventScroll:true});};
          show();
        })();
        """;
}
