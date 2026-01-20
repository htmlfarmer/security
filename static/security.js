    // LLM server URL for direct browser calls (override via env LLM_SERVER_URL)
    const LLM_SERVER_URL = '<?php echo htmlspecialchars(getenv("LLM_SERVER_URL") ?: "http://ashy.tplinkdns.com:5005/ask"); ?>';
    // System prompt for follow-up questions (requires structured JSON)
    const FOLLOWUP_SYSTEM_PROMPT = '<?php echo htmlspecialchars("You are a concise security analyst. Respond ONLY with a JSON object with keys: \\"answer\\" (string), \\"severity\\" (High|Medium|Low), and \\"confidence\\" (a number between 0.0 and 1.0). Do not include any other text outside the JSON."); ?>';
    // Helper: validate structured response contains required fields
    function validateStructured(parsed){
      const required = ['answer','severity','confidence'];
      const missing = [];
      if (!parsed || typeof parsed !== 'object') { return {ok:false, missing: required.slice(), msg: 'Not an object'}; }
      required.forEach(k => { if (!(k in parsed)) missing.push(k); });
      return { ok: missing.length === 0, missing: missing };
    }
    async function loadScripts(){
      const r = await fetch('?action=scripts');
      const data = await r.json();
      const container = document.getElementById('tests'); container.innerHTML='';
        data.scripts.forEach(s=>{
          const id='chk_'+s;
          const label=document.createElement('label'); label.className='test-card'; label.setAttribute('data-key', s);
          const filename = (data.labels && data.labels[s]) ? data.labels[s] : '';
          const icon = (data.icons && data.icons[s]) ? data.icons[s] : '🔎';
          label.innerHTML=`<input type="checkbox" id="${id}" value="${s}"><span class="icon">${icon}</span><div class="meta"><strong>${s}</strong><small>${filename}</small><span class="status">Idle</span></div>`;
          container.appendChild(label);
        });
    }

    async function runPayload(payload){
      const resp = await fetch('', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
      return await resp.json();
    }

    function createOrUpdateEntry(entry){
      const res=document.getElementById('results');
      let el = document.querySelector(`section.script-result[data-script="${entry.script}"]`);
      if (!el) {
        el = document.createElement('section'); el.className='script-result'; el.setAttribute('data-script', entry.script);
        const h=document.createElement('h4'); h.textContent = entry.script; el.appendChild(h);
          const cmdPre = document.createElement('pre'); cmdPre.className='cmd'; cmdPre.style.background='#f0f8ff'; cmdPre.style.padding='6px'; cmdPre.style.borderLeft='4px solid #cce'; cmdPre.style.display='none'; cmdPre.style.whiteSpace='pre-wrap'; el.appendChild(cmdPre);
        const pre=document.createElement('pre'); pre.className='stdout'; el.appendChild(pre);
        const err=document.createElement('pre'); err.className='stderr'; el.appendChild(err);
        const findings=document.createElement('div'); findings.className='findings'; el.appendChild(findings);
        res.appendChild(el);
      }
      el.querySelector('pre.stdout').textContent = entry.stdout || '';
      const errEl = el.querySelector('pre.stderr'); errEl.textContent = entry.stderr || ''; errEl.style.display = entry.stderr ? 'block' : 'none';
      const fEl = el.querySelector('.findings'); if (entry.findings && entry.findings.length){ fEl.innerHTML = '<strong>Findings:</strong><ul>' + entry.findings.map(x=>`<li>${x}</li>`).join('') + '</ul>'; } else { fEl.innerHTML = ''; }
      // AI analysis
      let aiEl = el.querySelector('.ai-analysis');
      if (!aiEl) { aiEl = document.createElement('div'); aiEl.className = 'ai-analysis'; aiEl.style.marginTop = '8px'; aiEl.style.background = '#fff8f0'; aiEl.style.padding = '10px'; aiEl.style.borderLeft = '4px solid #ffc107'; el.appendChild(aiEl); }
      if (entry.ai_analysis) {
        // Try to parse raw assistant reply (entry.ai_raw) or ai_analysis as JSON and render human-friendly fields
        let rendered = '';
        let rawText = entry.ai_raw || entry.ai_analysis || '';
        let parsed = null;
        try { parsed = JSON.parse(rawText); } catch (e) { parsed = null; }
        if (parsed && typeof parsed === 'object') {
          const parts = [];
          if (parsed.summary) parts.push('Summary: ' + parsed.summary);
          if (parsed.remediation) {
            if (Array.isArray(parsed.remediation)) parts.push('Remediation: ' + parsed.remediation.join('; ')); else parts.push('Remediation: ' + parsed.remediation);
          }
          if (parsed.notes) parts.push('Notes: ' + parsed.notes);
          if (parts.length) rendered = '<div style="white-space:pre-wrap;">' + parts.join('\n\n') + '</div>';
          else rendered = '<pre style="white-space:pre-wrap;">' + JSON.stringify(parsed, null, 2) + '</pre>';
        } else {
          // fallback: show the already-prepared analysis string (may be machine-concatenated by server)
          rendered = '<div style="white-space:pre-wrap;">' + entry.ai_analysis + '</div>';
        }
        aiEl.innerHTML = '<strong>AI SECURITY ANALYSIS:</strong><div style="margin-top:6px;">' + rendered + '</div>';
      } else { aiEl.innerHTML = ''; }
      // show command that was executed (if available)
      const cmdEl = el.querySelector('pre.cmd'); if (entry.cmd) { cmdEl.textContent = entry.cmd; cmdEl.style.display = 'block'; } else { cmdEl.style.display = 'none'; }
      // raw debug area (hidden unless "Show LLM debug" checked)
      let rawEl = el.querySelector('.ai-raw');
      if (!rawEl) { rawEl = document.createElement('div'); rawEl.className = 'ai-raw'; rawEl.style.marginTop = '8px'; rawEl.style.background = '#f6f6f6'; rawEl.style.padding = '8px'; rawEl.style.borderLeft = '4px solid #ccc'; rawEl.style.display = 'none'; el.appendChild(rawEl); }
      if (entry.ai_raw) { rawEl.textContent = entry.ai_raw; } else { rawEl.textContent = ''; }
      // toggle visibility based on UI checkbox
      const showDebug = document.getElementById('show-llm-debug');
      if (showDebug && showDebug.checked && rawEl.textContent) rawEl.style.display = 'block'; else rawEl.style.display = 'none';

      // Follow-up UI: button -> show textarea
      let followWrap = el.querySelector('.followup-wrap');
      if (!followWrap) {
        followWrap = document.createElement('div'); followWrap.className='followup-wrap'; followWrap.style.marginTop='8px';
        const btn = document.createElement('button'); btn.textContent='Ask follow-up'; btn.className='btn ghost'; btn.style.marginRight='8px';
        const area = document.createElement('textarea'); area.rows=3; area.style.width='100%'; area.style.display='none'; area.placeholder='Ask a follow-up question about this test...';
        const send = document.createElement('button'); send.textContent='Send'; send.className='btn'; send.style.display='none'; send.style.marginTop='6px';
        const respDiv = document.createElement('div'); respDiv.className='followup-response'; respDiv.style.marginTop='8px';
        followWrap.appendChild(btn); followWrap.appendChild(area); followWrap.appendChild(send); followWrap.appendChild(respDiv);
        el.appendChild(followWrap);

        btn.addEventListener('click', ()=>{ if (area.style.display==='none'){ area.style.display='block'; send.style.display='inline-block'; area.focus(); } else { area.style.display='none'; send.style.display='none'; } });
        send.addEventListener('click', async ()=>{
          const q = area.value && area.value.trim(); if (!q) { alert('Enter a question'); return; }
          send.disabled = true; send.textContent = 'Asking...';
          try {
            // Build a prompt including context and the user's question
            const prompt_text = `Follow-up question about script: ${entry.script}\nContext:\n${(entry.ai_raw || entry.stdout || '').slice(0,2000)}\n\nQuestion:\n${q}`;
            // Respect response mode: structured vs free-text
            const mode = (document.getElementById('llm-response-mode') && document.getElementById('llm-response-mode').value) || 'structured';
            const payload = { prompt: prompt_text };
            if (mode === 'structured') payload.system_prompt = FOLLOWUP_SYSTEM_PROMPT;
            const r = await fetch(LLM_SERVER_URL, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
            const j = await r.json();
            let display = 'No reply';
            let rawResp = '';
            if (j && typeof j.response !== 'undefined') {
              rawResp = String(j.response || '');
              // Try to parse any JSON reply and render as human-readable fields if possible
              let parsed = null;
              try { parsed = JSON.parse(rawResp); } catch (err) { parsed = null; }
              if (parsed && typeof parsed === 'object') {
                // Prefer fields summary/remediation/notes if present
                let parts = [];
                if (parsed.summary) parts.push('Summary: ' + parsed.summary);
                if (parsed.remediation) {
                  if (Array.isArray(parsed.remediation)) parts.push('Remediation: ' + parsed.remediation.join('; ')); else parts.push('Remediation: ' + parsed.remediation);
                }
                if (parsed.notes) parts.push('Notes: ' + parsed.notes);
                // If we assembled parts, show them nicely; otherwise fall back to showing parsed JSON
                if (parts.length) {
                  display = '<div style="white-space:pre-wrap;">' + parts.join('\n\n') + '</div>';
                } else if (mode === 'structured') {
                  // existing structured validation for answer/severity/confidence
                  const v = validateStructured(parsed);
                  let warn = '';
                  if (!v.ok) { warn = `<div style="color:#a00;margin-bottom:8px">Warning: structured response missing fields: ${v.missing.join(', ')}</div>`; }
                  display = warn + '<pre style="white-space:pre-wrap;">' + JSON.stringify(parsed, null, 2) + '</pre>';
                } else {
                  display = '<pre style="white-space:pre-wrap;">' + JSON.stringify(parsed, null, 2) + '</pre>';
                }
              } else {
                // non-JSON reply
                if (mode === 'structured') {
                  display = '<div style="color:#a00;margin-bottom:8px">Warning: expected JSON structured reply but assistant returned non-JSON text.</div><pre style="white-space:pre-wrap;">' + rawResp + '</pre>';
                } else {
                  display = '<pre style="white-space:pre-wrap;">' + rawResp + '</pre>';
                }
              }
            }
            respDiv.innerHTML = '<strong>Follow-up reply:</strong>' + display;
            // show raw debug if enabled
            if (document.getElementById('show-llm-debug') && document.getElementById('show-llm-debug').checked && rawResp) {
              const dbg = document.createElement('pre'); dbg.style.whiteSpace='pre-wrap'; dbg.textContent = rawResp; respDiv.appendChild(dbg);
            }
          } catch (e) {
            respDiv.innerHTML = '<span style="color:#a00">Request failed: '+String(e)+'</span>';
          } finally { send.disabled = false; send.textContent='Send'; }
        });
      }
      // update card status
      setCardStatus(entry.script, entry.stderr ? 'Error' : (entry.findings && entry.findings.length ? 'Done' : 'Done'), entry.stderr ? 'error' : 'done');
    }

    function setCardStatus(script, status, cls){
      const card = document.querySelector(`#tests label.test-card[data-key="${script}"]`);
      if (!card) return;
      const st = card.querySelector('.status'); if (st) st.textContent = status;
      card.classList.remove('running','done','error'); if (cls) card.classList.add(cls);
    }

    function setCardRunning(script){
      const card = document.querySelector(`#tests label.test-card[data-key="${script}"]`);
      if (!card) return;
      const st = card.querySelector('.status'); if (st) st.innerHTML = 'Running <span class="spinner"></span>';
      card.classList.remove('done','error'); card.classList.add('running');
    }

    // per-card progress management
    const _cardProgress = {};
    function createCardProgress(script, timeoutSec){
      const card = document.querySelector(`#tests label.test-card[data-key="${script}"]`);
      if (!card) return;
      // avoid duplicate
      if (card.querySelector('.card-progress')) return;
      const barWrap = document.createElement('div'); barWrap.className='card-progress'; barWrap.style.marginTop='8px'; barWrap.style.height='6px'; barWrap.style.background='#f0f6ff'; barWrap.style.borderRadius='6px';
      const bar = document.createElement('div'); bar.className='card-progress-bar'; bar.style.width='0%'; bar.style.height='6px'; bar.style.background='linear-gradient(90deg,var(--accent),#6cc1ff)'; bar.style.borderRadius='6px'; barWrap.appendChild(bar);
      card.appendChild(barWrap);
      const start = Date.now();
      const timeoutMs = (timeoutSec||60)*1000;
      _cardProgress[script] = {interval:setInterval(()=>{
        const elapsed = Date.now()-start; const pct = Math.min(99, Math.floor((elapsed/timeoutMs)*100)); bar.style.width = pct+'%';
      }, 500), bar: bar};
    }

    function finishCardProgress(script){
      const p = _cardProgress[script]; if (!p) return; clearInterval(p.interval); p.bar.style.width = '100%'; delete _cardProgress[script];
    }

    async function runSelected(){
      const url=document.getElementById('url').value;
      const checks=Array.from(document.querySelectorAll('#tests input:checked')).map(i=>i.value);
      const ports = document.getElementById('ports').value;
      if(!url){alert('Enter a target URL'); return;}
      if (!checks.length) { alert('Select at least one test'); return; }
      // clear previous results and summary
      document.getElementById('results').innerHTML = '<em>Running...</em>'; document.getElementById('summary').innerHTML = '';
      document.getElementById('ai-console').innerHTML = '';

      const resp = await fetch('?stream=1', {method:'POST', headers:{'Content-Type':'application/json','X-Stream':'1'}, body: JSON.stringify({url, tests: checks, ports})});
      if (!resp.body) { alert('Streaming not available; server did not return a stream.'); return; }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder(); let buf = '';
      while(true){ const {value, done} = await reader.read(); if (done) break; buf += decoder.decode(value, {stream:true}); let lines = buf.split(/\n/); buf = lines.pop(); for(const line of lines){ if(!line) continue; if (line === 'STREAM-START') { document.getElementById('results').innerHTML = ''; continue; } if (line === 'STREAM-END') continue; try{ processStreamLine(JSON.parse(line)); } catch(e){ console.error('parse', e, line); } } }
    }

    async function runLevel(){
      const url=document.getElementById('url').value; const level=document.getElementById('level').value;
      const ports = document.getElementById('ports').value;
      if(!url){alert('Enter a target URL'); return;}
      // clear previous results and summary
      document.getElementById('results').innerHTML = ''; document.getElementById('summary').innerHTML = '';
      // mark all cards running visually (server will emit start/result for actual ones)
      Array.from(document.querySelectorAll('#tests input')).map(i=>i.value).forEach(s=>setCardRunning(s));
      // create per-card progress placeholders
      Array.from(document.querySelectorAll('#tests input')).map(i=>i.value).forEach(s=>createCardProgress(s, 60));

      window.currentAbortController = new AbortController();
      const resp = await fetch('?stream=1', {method:'POST', headers:{'Content-Type':'application/json','X-Stream':'1'}, body: JSON.stringify({url, level, ports, scan_type: document.getElementById('nmap-scan-type').value, include_mitigation: document.getElementById('include-mitigation').checked, prefer_connect_scan: document.getElementById('prefer-connect-scan').checked, llm: document.getElementById('enable-llm').checked, llm_mode: (document.getElementById('llm-response-mode') && document.getElementById('llm-response-mode').value) || 'structured'}), signal: window.currentAbortController.signal});
      if (!resp.body) { alert('Streaming not available; server did not return a stream.'); return; }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder(); let buf = '';
      let totalScripts = 0; let completedScripts = 0;
      while(true){ const {value, done} = await reader.read(); if (done) break; buf += decoder.decode(value, {stream:true}); let lines = buf.split(/\n/); buf = lines.pop(); for(const line of lines){ if(!line) continue; if (line === 'STREAM-START' || line === 'STREAM-END') continue; try{ const obj = JSON.parse(line);
                if (obj.type === 'chunk'){
                  const script = obj.script;
                  setCardRunning(script);
                  let el = document.querySelector(`section.script-result[data-script="${script}"]`);
                  if (!el) { createOrUpdateEntry({script: script, stdout: '', stderr: '', findings: []}); el = document.querySelector(`section.script-result[data-script="${script}"]`); }
                  const pre = el.querySelector('pre.stdout'); pre.textContent = (pre.textContent || '') + (obj.chunk || '');
                  if (obj.stderr) { const errEl = el.querySelector('pre.stderr'); errEl.textContent = obj.stderr; errEl.style.display = 'block'; }
                } else if (obj.type === 'start'){
                  setCardRunning(obj.script);
                  createCardProgress(obj.script, obj.timeout);
                  totalScripts++;
                } else if (obj.type === 'result'){
                  createOrUpdateEntry(obj.entry);
                  finishCardProgress(obj.entry.script);
                  completedScripts++;
                  const pct = totalScripts ? Math.round((completedScripts/totalScripts)*100) : 100;
                  document.getElementById('global-progress-bar').style.width = pct + '%';
                } else if (obj.type === 'summary'){
                  const sum=document.getElementById('summary'); if(obj.summary && obj.summary.length){ const ul=document.createElement('ul'); obj.summary.forEach(s=>{const li=document.createElement('li'); li.textContent=s; ul.appendChild(li)}); sum.appendChild(ul);} else sum.textContent='No findings';
                  if (obj.llm_ideas && obj.llm_ideas.length){ const h=document.createElement('h4'); h.textContent='LLM Ideas & Analysis'; sum.appendChild(h); const ol=document.createElement('ol'); obj.llm_ideas.forEach(i=>{ const li=document.createElement('li'); li.innerHTML = `<strong>${i.script}:</strong> ${i.analysis}`; ol.appendChild(li); }); sum.appendChild(ol); }
                }
            } catch(e){ console.error('parse', e, line); }
        }}
      document.getElementById('global-progress-bar').style.width = '100%';
      // finalize statuses for all
      Array.from(document.querySelectorAll('#tests input')).map(i=>i.value).forEach(s=>{ finishCardProgress(s); setCardStatus(s, 'Done', 'done'); });
      window.currentAbortController = null;
    }

    // Run all via streaming fetch; server emits JSON-per-line for each result and a summary
    async function runAll(){
      const url=document.getElementById('url').value; if(!url){alert('Enter a target URL'); return;}
      document.getElementById('results').innerHTML = '<em>Running...</em>'; document.getElementById('summary').innerHTML = '';
      document.getElementById('ai-console').innerHTML = '';

      const r = await fetch('?action=scripts'); const data = await r.json();
      const resp = await fetch('?stream=1', {method:'POST', headers:{'Content-Type':'application/json','X-Stream':'1'}, body: JSON.stringify({url, tests: data.scripts})});
      if (!resp.body) { alert('Streaming not available; server did not return a stream.'); return; }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder(); let buf = '';
      while(true){ const {value, done} = await reader.read(); if (done) break; buf += decoder.decode(value, {stream:true}); let lines = buf.split(/\n/); buf = lines.pop(); for(const line of lines){ if(!line) continue; if (line === 'STREAM-START') { document.getElementById('results').innerHTML = ''; continue; } if (line === 'STREAM-END') continue; try{ processStreamLine(JSON.parse(line)); } catch(e){ console.error('parse', e, line); } } }
    }

    function processStreamLine(data) {
      const resDiv = document.getElementById('results');
      const sumDiv = document.getElementById('summary');
      const aiConsole = document.getElementById('ai-console');

      if (data.type === 'start') {
        let scriptDiv = document.getElementById(`script-${data.script}`);
        if (!scriptDiv) {
          scriptDiv = document.createElement('div');
          scriptDiv.id = `script-${data.script}`;
          scriptDiv.innerHTML = `<h4>${data.script}</h4><pre></pre>`;
          resDiv.appendChild(scriptDiv);
        }
      } else if (data.type === 'chunk') {
        const scriptDiv = document.getElementById(`script-${data.script}`);
        if (scriptDiv) {
          const pre = scriptDiv.querySelector('pre');
          pre.textContent += data.chunk;
        }
      } else if (data.type === 'result') {
        const scriptDiv = document.getElementById(`script-${data.entry.script}`);
        if (scriptDiv) {
          // Final result can be processed here if needed
        }
      } else if (data.type === 'summary') {
        if(data.summary && data.summary.length){ const ul=document.createElement('ul'); data.summary.forEach(s=>{const li=document.createElement('li'); li.textContent=s; ul.appendChild(li)}); sumDiv.appendChild(ul);} else sumDiv.textContent='No findings';
      } else if (data.type === 'llm_request') {
        const pre = document.createElement('pre');
        pre.textContent = `[${data.script}] PROMPT:\n${data.prompt}`;
        aiConsole.appendChild(pre);
      }
    }

    function renderResults(data){ const sum=document.getElementById('summary'); const res=document.getElementById('results'); res.innerHTML=''; sum.innerHTML=''; if(data.summary && data.summary.length){ const ul=document.createElement('ul'); data.summary.forEach(s=>{const li=document.createElement('li'); li.textContent=s; ul.appendChild(li)}); sum.appendChild(ul);} else sum.textContent='No findings'; data.results.forEach(r=>{createOrUpdateEntry(r);}); }

    document.getElementById('run-selected').addEventListener('click', runSelected);
    document.getElementById('run-level').addEventListener('click', runLevel);
    document.getElementById('run-all').addEventListener('click', runAll);
    document.getElementById('stop-all').addEventListener('click', async ()=>{
      try { await fetch('?action=stop_all', { method: 'POST' }); } catch(e){ console.error('stop request failed', e); }
      if (window.currentAbortController) { window.currentAbortController.abort(); }
    });
    document.getElementById('select-all').addEventListener('click', ()=>{ document.querySelectorAll('#tests input[type=checkbox]').forEach(i=>i.checked=true); });
    document.getElementById('clear-selection').addEventListener('click', ()=>{ document.querySelectorAll('#tests input[type=checkbox]').forEach(i=>i.checked=false); });
    loadScripts();
  
    // Handler for quick global LLM question (direct browser call)
    document.getElementById('ask-llm-global').addEventListener('click', async function(){
      const qEl = document.getElementById('llm-global-question');
      const question = qEl.value && qEl.value.trim();
      if (!question) { alert('Enter a question'); return; }
      const respDivId = 'llm-global-response';
      let respDiv = document.getElementById(respDivId);
      if (!respDiv) { respDiv = document.createElement('div'); respDiv.id = respDivId; respDiv.style.marginTop='12px'; document.querySelector('.controls').appendChild(respDiv); }
      respDiv.innerHTML = '<em>Asking...</em>';
      try {
        const prompt_text = `General security question:\n\n${question}`;
        const mode = (document.getElementById('llm-response-mode') && document.getElementById('llm-response-mode').value) || 'structured';
        const payload = { prompt: prompt_text };
        if (mode === 'structured') payload.system_prompt = FOLLOWUP_SYSTEM_PROMPT;
        const r = await fetch(LLM_SERVER_URL, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
        if (!r.ok) {
          respDiv.innerHTML = `<span style="color:#a00">LLM request failed: ${r.status}</span>`;
          return;
        }
        const j = await r.json();
        let rawResp = '';
        let display = '';
        if (j && typeof j.response !== 'undefined') {
          rawResp = String(j.response || '');
          let parsed = null;
          try { parsed = JSON.parse(rawResp); } catch (err) { parsed = null; }
          if (parsed && typeof parsed === 'object') {
            let parts = [];
            if (parsed.summary) parts.push('Summary: ' + parsed.summary);
            if (parsed.remediation) {
              if (Array.isArray(parsed.remediation)) parts.push('Remediation: ' + parsed.remediation.join('; ')); else parts.push('Remediation: ' + parsed.remediation);
            }
            if (parsed.notes) parts.push('Notes: ' + parsed.notes);
            if (parts.length) {
              display = '<div style="white-space:pre-wrap;">' + parts.join('\n\n') + '</div>';
            } else if (mode === 'structured') {
              const v = validateStructured(parsed);
              let warn = ''; if (!v.ok) { warn = `<div style="color:#a00;margin-bottom:8px">Warning: structured response missing fields: ${v.missing.join(', ')}</div>`; }
              display = warn + '<pre style="white-space:pre-wrap;">' + JSON.stringify(parsed, null, 2) + '</pre>';
            } else {
              display = '<pre style="white-space:pre-wrap;">' + JSON.stringify(parsed, null, 2) + '</pre>';
            }
          } else {
            display = '<pre style="white-space:pre-wrap;">' + rawResp + '</pre>';
          }
        } else {
          display = '<span>No response</span>';
        }
        respDiv.innerHTML = '<strong>LLM answer:</strong>' + display;
        if (document.getElementById('show-llm-debug') && document.getElementById('show-llm-debug').checked && rawResp) {
          const dbg = document.createElement('pre'); dbg.style.whiteSpace='pre-wrap'; dbg.textContent = rawResp; respDiv.appendChild(dbg);
        }
      } catch (e) {
        respDiv.innerHTML = '<span style="color:#a00">Request failed: '+String(e)+'</span>';
      }
    });
  