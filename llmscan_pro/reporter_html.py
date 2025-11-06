import os, html

def generate_html(results, out_path):
    rows=[]
    for r in results:
        rows.append('<tr>'+ f'<td>{html.escape(r.get("probe_id",""))}</td>' + f'<td>{html.escape(r.get("family",""))}</td>' + f'<td>{html.escape(r.get("verdict",""))}</td>' + f'<td>{html.escape(str(round(r.get("confidence",0),2)))}</td>' + f'<td>{html.escape(r.get("evidence_snippet",""))}</td>' + f'<td>{html.escape(",".join([d.get("id","") for d in r.get("retrieved_docs",[])]))}</td>' + '</tr>')
    html_doc = f"""<html><head><meta charset='utf-8'><title>llmscan_pro report</title></head><body><h1>llmscan_pro report</h1><table border='1' cellpadding='4'><tr><th>probe</th><th>family</th><th>verdict</th><th>conf</th><th>evidence</th><th>retrieved</th></tr>{''.join(rows)}</table></body></html>"""
    os.makedirs(os.path.dirname(out_path) or '.', exist_ok=True)
    with open(out_path,'w',encoding='utf-8') as fh: fh.write(html_doc)
