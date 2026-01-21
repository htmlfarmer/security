// Use global configuration if available, otherwise fall back to defaults
    const LLM_SERVER_URL = window.LLM_SERVER_URL || 'http://ashy.tplinkdns.com:5005/ask';
    const FOLLOWUP_SYSTEM_PROMPT = window.FOLLOWUP_SYSTEM_PROMPT || 'You are a concise security analyst. Respond ONLY with a JSON object with keys: "answer" (string), "severity" (High|Medium|Low), and "confidence" (a number between 0.0 and 1.0).';
    // Helper: validate structured response contains required fields
    function validateStructured(parsed){
      const required = ['answer','severity','confidence'];
      const missing = [];
      if (!parsed || typeof parsed !== 'object') { return {ok:false, missing: required.slice(), msg: 'Not an object'}; }
      required.forEach(k => { if (!(k in parsed)) missing.push(k); });
      return { ok: missing.length === 0, missing: missing };
    }

    // Track which scripts we've already auto-asked during this run to avoid duplicates
    const _autoAsked = new Set();

    // Automatically ask the LLM a follow-up question for a script result and attach the reply to the UI
    async function autoAskFollowup(entry) {
      try {
        if (!document.getElementById('enable-llm') || !document.getElementById('enable-llm').checked) return;
        if (!entry || !entry.script) return;
        const script = entry.script;
        if (_autoAsked.has(script)) return;
        _autoAsked.add(script);

        const mode = (document.getElementById('llm-response-mode') && document.getElementById('llm-response-mode').value) || 'structured';
      const provider = document.getElementById('llm-provider')?.value || '';
        const contextText = (entry.ai_raw || entry.ai_analysis || entry.stdout || '').slice(0,2000);
        const prompt = `Analyze the results of the security test "${script}". Provide a concise JSON object with keys: \"summary\" (string), \"remediation\" (array of strings), and \"notes\" (string). Context:\n${contextText}`;

        const payload = { prompt: prompt, provider: provider, conversation: [{ role: 'assistant', content: contextText }] };
        if (mode === 'structured') payload.system_prompt = FOLLOWUP_SYSTEM_PROMPT;

        const aiConsole = document.getElementById('ai-console') || (function(){ const d=document.createElement('div'); d.id='ai-console'; d.style.marginTop='8px'; const summary=document.getElementById('summary'); (summary && summary.parentNode) ? summary.parentNode.insertBefore(d, summary.nextSibling) : document.body.appendChild(d); return d; })();
        const statusPre = document.createElement('pre'); statusPre.textContent = `[${script}] LLM: Asking follow-up...`; statusPre.style.color = '#0056b3'; aiConsole.appendChild(statusPre);

        const target = (document.getElementById('url') && document.getElementById('url').value) ? document.getElementById('url').value : '';
        const postBody = { script: script, question: prompt, context: contextText, provider: provider, target: target };
        const r = await fetch('?action=ask_llm', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(postBody) });
        if (!r.ok) {
          statusPre.textContent = `[${script}] LLM: Request failed (${r.status})`;
          statusPre.style.color = '#a00';
          return;
        }
        const j = await r.json();
        const rawResp = (j && j.llm && typeof j.llm.raw !== 'undefined') ? String(j.llm.raw||'') : (j && j.llm && typeof j.llm.response !== 'undefined' ? String(j.llm.response||'') : '');
        statusPre.textContent = `[${script}] LLM: Success`;
        statusPre.style.color = '#28a745';
        if (j && j.saved_to) {
          const note = document.createElement('div'); note.style.fontSize='12px'; note.style.color='#666'; note.style.marginTop='6px'; note.textContent = `Saved to: ${j.saved_to}`; aiConsole.appendChild(note);
        }

        // attach reply to per-script UI
        let sec = document.querySelector(`section.script-result[data-script="${script}"]`);
        if (!sec) { createOrUpdateEntry(entry); sec = document.querySelector(`section.script-result[data-script="${script}"]`); }
        let aiAnal = sec.querySelector('.ai-analysis'); if (!aiAnal) { aiAnal = document.createElement('div'); aiAnal.className='ai-analysis'; aiAnal.style.marginTop='8px'; aiAnal.style.background='#fff8f0'; aiAnal.style.padding='10px'; aiAnal.style.borderLeft='4px solid #ffc107'; sec.appendChild(aiAnal); }

        // attempt to parse JSON and render summary/remediation/notes
        let display = rawResp;
        try { const parsed = JSON.parse(rawResp); if (parsed && typeof parsed === 'object') { const parts=[]; if (parsed.summary) parts.push('Summary: '+parsed.summary); if (parsed.remediation) parts.push('Remediation: '+(Array.isArray(parsed.remediation) ? parsed.remediation.join('; ') : parsed.remediation)); if (parsed.notes) parts.push('Notes: '+parsed.notes); if (parts.length) display = '<div style="white-space:pre-wrap;">'+parts.join('\n\n')+'</div>'; else display = '<pre style="white-space:pre-wrap;">'+JSON.stringify(parsed,null,2)+'</pre>'; } } catch(e){ /* not JSON, show raw */ }
        aiAnal.innerHTML = '<strong>AI SECURITY ANALYSIS (auto):</strong><div style="margin-top:6px;">' + display + '</div>';

        // attach raw debug content for visibility when debug enabled
        let rawEl = sec.querySelector('.ai-raw'); if (!rawEl) { rawEl = document.createElement('div'); rawEl.className='ai-raw'; rawEl.style.marginTop = '8px'; rawEl.style.background = '#f6f6f6'; rawEl.style.padding = '8px'; rawEl.style.borderLeft = '4px solid #ccc'; sec.appendChild(rawEl); }
        rawEl.textContent = rawResp || '';
        rawEl.style.display = (document.getElementById('show-llm-debug') && document.getElementById('show-llm-debug').checked && rawEl.textContent) ? 'block' : 'none';

      } catch (e) { console.error('autoAskFollowup failed', e); }
    }

    // Ensure an ai-console container exists and return it
    function getAiConsole(){
      let aiConsole = document.getElementById('ai-console');
      if (!aiConsole) {
        aiConsole = document.createElement('div'); aiConsole.id = 'ai-console'; aiConsole.style.marginTop = '8px';
        const summary = document.getElementById('summary');
        if (summary && summary.parentNode) summary.parentNode.insertBefore(aiConsole, summary.nextSibling); else document.body.appendChild(aiConsole);
      }
      return aiConsole;
    }

    // Create or return a per-script ai-console section (includes textarea + send button + response area)
    function ensureAiConsoleSection(script, suggestedPrompt) {
      const aiConsole = getAiConsole();
      let sec = document.getElementById(`ai-console-${script}`);
      if (!sec) {
        sec = document.createElement('div'); sec.id = `ai-console-${script}`; sec.style.borderTop = '1px solid #eee'; sec.style.padding = '8px 0';
        const header = document.createElement('div'); header.innerHTML = `<strong>[${script}] Ask LLM follow-up</strong>`; header.style.marginBottom = '6px';
        const ta = document.createElement('textarea'); ta.rows = 3; ta.style.width = '100%'; ta.placeholder = 'Ask a follow-up question about this test...'; if (suggestedPrompt) ta.value = suggestedPrompt;
        const btn = document.createElement('button'); btn.textContent = 'Send'; btn.className = 'btn'; btn.style.marginTop = '6px'; btn.style.marginRight = '8px';
        const resp = document.createElement('div'); resp.className = 'ai-console-response'; resp.style.marginTop = '8px';
        sec.appendChild(header); sec.appendChild(ta); sec.appendChild(btn); sec.appendChild(resp);
        aiConsole.appendChild(sec);

        // Load any previously saved follow-ups for this script/target and render them
        (async () => {
          try {
            const target = (document.getElementById('url') && document.getElementById('url').value) ? document.getElementById('url').value : '';
            if (target) {
              const r = await fetch(`?action=get_followups&target=${encodeURIComponent(target)}&script=${encodeURIComponent(script)}`);
              if (r.ok) {
                const j = await r.json(); if (j && Array.isArray(j.followups) && j.followups.length) {
                  resp.innerHTML = '<strong>Previously saved follow-ups:</strong>';
                  j.followups.forEach(fu=>{
                    const d = document.createElement('div'); d.style.marginTop='8px'; d.innerHTML = `<em>${new Date((fu.timestamp||0)*1000).toISOString()}</em> — <strong>Q:</strong> ${(fu.question||'')}<br><pre>${(fu.response_raw||'')}</pre>`;
                    resp.appendChild(d);
                  });
                }
              }
            }
          } catch(e){ console.error('loading previous followups failed', e); }
        })();

        btn.addEventListener('click', async ()=>{
          const q = ta.value && ta.value.trim(); if (!q) { alert('Enter a question'); return; }
          btn.disabled = true; btn.textContent = 'Asking...';
          try { await sendFollowupQuestion(script, q, resp); } catch (e) { resp.innerHTML = `<span style="color:#a00">Request failed: ${String(e)}</span>`; }
          finally { btn.disabled = false; btn.textContent = 'Send'; }
        });
      }
      return sec;
    }

    // Send follow-up question using shared LLM call logic and attach reply to UI and per-script card
    async function sendFollowupQuestion(script, question, respContainer) {
      const mode = (document.getElementById('llm-response-mode') && document.getElementById('llm-response-mode').value) || 'structured';
const provider = document.getElementById('llm-provider')?.value || '';
      // Grab context from the per-script card if available
      const secCard = document.querySelector(`section.script-result[data-script="${script}"]`);
      const contextText = secCard ? ((secCard.querySelector('.ai-raw')?.textContent || secCard.querySelector('pre.stdout')?.textContent || '')).slice(0,2000) : '';
      const payload = { prompt: question, provider: provider, conversation: [{ role: 'assistant', content: contextText }] };
      if (mode === 'structured') payload.system_prompt = FOLLOWUP_SYSTEM_PROMPT;

      if (respContainer) {
        respContainer.innerHTML = `<em>Asking LLM...</em>`;
      }

      // POST to server-side ask_llm endpoint so the follow-up is persisted for reports
      const target = (document.getElementById('url') && document.getElementById('url').value) ? document.getElementById('url').value : '';
      const postBody = { script: script, question: question, context: contextText, provider: provider, target: target };
      const r = await fetch('?action=ask_llm', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(postBody) });
      if (!r.ok) {
        if (respContainer) respContainer.innerHTML = `<span style="color:#a00">LLM request failed: ${r.status}</span>`;
        throw new Error('LLM request failed');
      }
      const j = await r.json(); const rawResp = (j && j.llm && typeof j.llm.raw !== 'undefined') ? String(j.llm.raw||'') : (j && j.llm && typeof j.llm.response !== 'undefined' ? String(j.llm.response||'') : '');

      // Attach response to the ai-console area
      if (respContainer) {
        // attempt to format JSON structured replies nicely
        let display = rawResp;
        try { const parsed = JSON.parse(rawResp); if (parsed && typeof parsed === 'object') { let parts = []; if (parsed.summary) parts.push('Summary: ' + parsed.summary); if (parsed.remediation) parts.push('Remediation: ' + (Array.isArray(parsed.remediation) ? parsed.remediation.join('; ') : parsed.remediation)); if (parsed.notes) parts.push('Notes: ' + parsed.notes); if (parts.length) display = '<div style="white-space:pre-wrap;">' + parts.join('\n\n') + '</div>'; else display = '<pre style="white-space:pre-wrap;">' + JSON.stringify(parsed, null, 2) + '</pre>'; } } catch(e){ /* ignore parse errors */ }
        respContainer.innerHTML = '<strong>LLM reply:</strong>' + display;
        if (j && j.saved_to) {
          const note = document.createElement('div'); note.style.fontSize='12px'; note.style.color='#666'; note.style.marginTop='6px'; note.textContent = `Saved to: ${j.saved_to}`; respContainer.appendChild(note);
        }
        if (rawResp) { const dbg = document.createElement('pre'); dbg.style.whiteSpace = 'pre-wrap'; dbg.textContent = rawResp; dbg.setAttribute('data-raw','1'); dbg.style.display = (document.getElementById('show-llm-debug') && document.getElementById('show-llm-debug').checked) ? 'block' : 'none'; respContainer.appendChild(dbg); }
      }

      // Also attach reply into the per-script card AI analysis area for visibility
      if (secCard) {
        let aiAnal = secCard.querySelector('.ai-analysis'); if (!aiAnal) { aiAnal = document.createElement('div'); aiAnal.className='ai-analysis'; aiAnal.style.marginTop='8px'; aiAnal.style.background='#fff8f0'; aiAnal.style.padding='10px'; aiAnal.style.borderLeft='4px solid #ffc107'; secCard.appendChild(aiAnal); }
        aiAnal.innerHTML = '<strong>AI SECURITY ANALYSIS (follow-up):</strong><div style="margin-top:6px;">' + (respContainer ? respContainer.innerHTML : (rawResp || '')) + '</div>';
        let rawEl = secCard.querySelector('.ai-raw'); if (!rawEl) { rawEl = document.createElement('div'); rawEl.className='ai-raw'; rawEl.style.marginTop = '8px'; rawEl.style.background = '#f6f6f6'; rawEl.style.padding = '8px'; rawEl.style.borderLeft = '4px solid #ccc'; secCard.appendChild(rawEl); }
        rawEl.textContent = rawResp || '';
        rawEl.style.display = (document.getElementById('show-llm-debug') && document.getElementById('show-llm-debug').checked && rawEl.textContent) ? 'block' : 'none';
      }

      return j;
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
        // Header with visible follow-up button
        const header = document.createElement('div'); header.style.display = 'flex'; header.style.alignItems = 'center'; header.style.justifyContent = 'space-between';
        const title = document.createElement('h4'); title.textContent = entry.script; title.style.margin = '0';
        const followBtn = document.createElement('button'); followBtn.textContent = 'Ask follow-up'; followBtn.className = 'btn ghost'; followBtn.style.marginLeft = '8px';
        followBtn.addEventListener('click', ()=>{
          // If LLM analysis is disabled, prompt user to enable it first
          const llmEnabled = document.getElementById('enable-llm') && document.getElementById('enable-llm').checked;
          if (!llmEnabled) {
            if (!confirm('LLM analysis is currently disabled. Enable LLM analysis to ask follow-up questions?')) return;
            document.getElementById('enable-llm').checked = true;
          }
          // Toggle/create follow-up UI below the card
          let fw = el.querySelector('.followup-wrap');
          if (!fw) {
            // createOrUpdateEntry will create the followup UI when invoked with the current entry
            createOrUpdateEntry(entry);
            setTimeout(()=>{ const fw2 = el.querySelector('.followup-wrap'); if (fw2) { const btn = fw2.querySelector('button'); if (btn) btn.click(); } }, 50);
          } else {
            const toggleBtn = fw.querySelector('button'); if (toggleBtn) toggleBtn.click();
          }
        });
        const right = document.createElement('div'); right.style.display='flex'; right.style.alignItems='center'; right.appendChild(followBtn);
        header.appendChild(title); header.appendChild(right); el.appendChild(header);

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
            // Respect response mode: structured vs free-text
            const mode = (document.getElementById('llm-response-mode') && document.getElementById('llm-response-mode').value) || 'structured';
            const provider = document.getElementById('llm-provider')?.value || '';
            // Send the previous assistant reply as conversation context for better follow-ups
            const contextText = (entry.ai_raw || entry.ai_analysis || entry.stdout || '').slice(0,2000);
            const payload = { prompt: q, provider: provider, conversation: [{ role: 'assistant', content: contextText }] };
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
            // show raw debug (attach as data-raw so global toggle can control visibility)
            if (rawResp) {
              const dbg = document.createElement('pre'); dbg.style.whiteSpace='pre-wrap'; dbg.textContent = rawResp; dbg.setAttribute('data-raw','1'); dbg.style.display = (document.getElementById('show-llm-debug') && document.getElementById('show-llm-debug').checked) ? 'block' : 'none'; respDiv.appendChild(dbg);
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
      const url = document.getElementById('url').value;
      const checks = Array.from(document.querySelectorAll('#tests input:checked')).map(i=>i.value);
      const ports = document.getElementById('ports').value;
      if(!url){alert('Enter a target URL'); return;}
      if (!checks.length) { alert('Select at least one test'); return; }
      
      const llm_url_ovr = document.getElementById('llm-url-override')?.value;
      const llm_timeout_ovr = document.getElementById('llm-timeout-override')?.value;
      const llm_retries_ovr = document.getElementById('llm-retries-override')?.value;

      // clear previous results and summary
      document.getElementById('results').innerHTML = ''; document.getElementById('summary').innerHTML = '';
      _autoAsked.clear();
      const aiConsole = document.getElementById('ai-console');
      if (aiConsole) aiConsole.innerHTML = ''; // safe: only clear if present

      // mark selected cards running
      checks.forEach(s=>setCardRunning(s));
      // setup per-card progress and global progress
      let totalScripts = checks.length; let completedScripts = 0;
      document.getElementById('global-progress-bar').style.width = '5%';

      // create an AbortController for this run so the UI can cancel it
      window.currentAbortController = new AbortController();
      const resp = await fetch('?stream=1', {method:'POST', headers:{'Content-Type':'application/json','X-Stream':'1'}, body: JSON.stringify({
        url, 
        tests: checks, 
        ports, 
        scan_type: document.getElementById('nmap-scan-type').value, 
        include_mitigation: document.getElementById('include-mitigation').checked, 
        prefer_connect_scan: document.getElementById('prefer-connect-scan').checked, 
        llm: document.getElementById('enable-llm').checked, 
        llm_mode: (document.getElementById('llm-response-mode') && document.getElementById('llm-response-mode').value) || 'structured',
        llm_url: llm_url_ovr,
        llm_timeout: llm_timeout_ovr,
        llm_retries: llm_retries_ovr,
        llm_max_excerpt: document.getElementById('llm-max-excerpt')?.value
      }), signal: window.currentAbortController.signal});
      if (!resp.body) { alert('Streaming not available; server did not return a stream.'); return; }
      const reader = resp.body.getReader();
      const decoder = new TextDecoder(); let buf = '';
      while(true){ const {value, done} = await reader.read(); if (done) break; buf += decoder.decode(value, {stream:true}); let lines = buf.split(/\n/); buf = lines.pop(); for(const line of lines){ if(!line) continue; if (line === 'STREAM-START') { document.getElementById('results').innerHTML = ''; continue; } if (line === 'STREAM-END') continue; try{ 
        const obj = JSON.parse(line);
        processStreamLine(obj);
        if (obj.type === 'start') {
          createCardProgress(obj.script, obj.timeout);
        } else if (obj.type === 'result') {
          finishCardProgress(obj.entry.script);
          completedScripts++;
          const pct = Math.round((completedScripts/totalScripts)*100);
          document.getElementById('global-progress-bar').style.width = pct + '%';
        }
      } catch(e){ console.error('parse', e, line); } } }
      document.getElementById('global-progress-bar').style.width = '100%';
      // finalize statuses for any remaining selected
      checks.forEach(s=>{ finishCardProgress(s); setCardStatus(s, 'Done', 'done'); });
      // clear controller
      window.currentAbortController = null;
    }

    async function runLevel(){
      const url=document.getElementById('url').value; const level=document.getElementById('level').value;
      const ports = document.getElementById('ports').value;
      if(!url){alert('Enter a target URL'); return;}
      // clear previous results and summary
      document.getElementById('results').innerHTML = ''; document.getElementById('summary').innerHTML = '';
      _autoAsked.clear();
      // mark all cards running visually (server will emit start/result for actual ones)
      Array.from(document.querySelectorAll('#tests input')).map(i=>i.value).forEach(s=>setCardRunning(s));
      // create per-card progress placeholders
      Array.from(document.querySelectorAll('#tests input')).map(i=>i.value).forEach(s=>createCardProgress(s, 60));

      window.currentAbortController = new AbortController();
      const resp = await fetch('?stream=1', {method:'POST', headers:{'Content-Type':'application/json','X-Stream':'1'}, body: JSON.stringify({
        url, 
        level, 
        ports, 
        scan_type: document.getElementById('nmap-scan-type').value, 
        include_mitigation: document.getElementById('include-mitigation').checked, 
        prefer_connect_scan: document.getElementById('prefer-connect-scan').checked, 
        llm: document.getElementById('enable-llm').checked, 
        llm_mode: (document.getElementById('llm-response-mode') && document.getElementById('llm-response-mode').value) || 'structured',
        llm_provider: document.getElementById('llm-provider')?.value || '',
        llm_url: llm_url_ovr,
        llm_timeout: llm_timeout_ovr,
        llm_retries: llm_retries_ovr,
        llm_max_excerpt: document.getElementById('llm-max-excerpt')?.value
      }), signal: window.currentAbortController.signal});
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
                  try { if (typeof autoAskFollowup === 'function') autoAskFollowup(obj.entry); } catch(e){ console.error('autoAskFollowup failed', e); }
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
      _autoAsked.clear();
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
        // automatically ask follow-up via LLM for this test result (if LLM enabled)
        try {
          if (typeof autoAskFollowup === 'function' && data.entry) {
            autoAskFollowup(data.entry);
          }
        } catch (e) { console.error('autoAskFollowup failed', e); }

        // ensure a per-script AI console section exists so users can ask follow-ups centrally
        try {
          const excerpt = (data.entry && (data.entry.ai_raw || data.entry.ai_analysis || data.entry.stdout)) ? ((data.entry.stdout || '').slice(0,300)) : '';
          const suggestion = excerpt ? `Analyze the following raw scanner output and identify security implications.\n\nRaw Output Excerpt (chars):\n${excerpt}` : '';
          ensureAiConsoleSection(data.entry.script, suggestion);
        } catch (e) { console.error('ensureAiConsoleSection failed', e); }
      } else if (data.type === 'summary') {
        if(data.summary && data.summary.length){ const ul=document.createElement('ul'); data.summary.forEach(s=>{const li=document.createElement('li'); li.textContent=s; ul.appendChild(li)}); sumDiv.appendChild(ul);} else sumDiv.textContent='No findings';
      } else if (data.type === 'llm_request') {
        // ensure we have an aiConsole to display prompts/debug
        let theConsole = aiConsole;
        if (!theConsole) {
          theConsole = document.getElementById('ai-console');
          if (!theConsole) {
            theConsole = document.createElement('div'); theConsole.id = 'ai-console'; theConsole.style.marginTop = '8px';
            const summary = document.getElementById('summary'); if (summary && summary.parentNode) summary.parentNode.insertBefore(theConsole, summary.nextSibling); else document.body.appendChild(theConsole);
          }
        }
        const pre = document.createElement('pre');
        pre.textContent = `[${data.script}] PROMPT:\n${data.prompt}`;
        theConsole.appendChild(pre);
      } else if (data.type === 'llm_status') {
        // status updates: waiting | success | error
        let theConsole = aiConsole || document.getElementById('ai-console');
        if (!theConsole) {
          theConsole = document.createElement('div'); theConsole.id = 'ai-console'; theConsole.style.marginTop='8px';
          const summary = document.getElementById('summary'); if (summary && summary.parentNode) summary.parentNode.insertBefore(theConsole, summary.nextSibling); else document.body.appendChild(theConsole);
        }
        let statusText = `[${data.script}] LLM: ${data.status}`;
        if (data.status === 'waiting') statusText = `[${data.script}] LLM: Waiting for AI reply (up to 90s)...`;
        if (data.provider) statusText += ` [${data.provider}]`;
        if (data.duration) statusText += ` in ${data.duration}s`;
        if (data.http_code) statusText += ` HTTP ${data.http_code}`;
        if (data.err) statusText += ` err: ${data.err}`;
        
        const preStatus = document.createElement('pre'); preStatus.textContent = statusText; 
        if (data.status === 'error') preStatus.style.color='#a00';
        else if (data.status === 'success') preStatus.style.color='#28a745';
        else preStatus.style.color='#0056b3';
        theConsole.appendChild(preStatus);
        
        // update per-script LLM status badge
        const sec = document.querySelector(`section.script-result[data-script="${data.script}"]`);
        if (sec) {
          let sEl = sec.querySelector('.ai-status'); if (!sEl) { sEl = document.createElement('div'); sEl.className='ai-status'; sEl.style.marginTop='6px'; sEl.style.fontSize='13px'; sec.appendChild(sEl); }
          sEl.textContent = statusText; 
          sEl.style.color = (data.status === 'error') ? '#a00' : (data.status === 'success' ? '#28a745' : '#0056b3');
        }
      } else if (data.type === 'llm_result') {
        let theConsole = aiConsole || document.getElementById('ai-console');
        if (!theConsole) { theConsole = document.createElement('div'); theConsole.id='ai-console'; theConsole.style.marginTop='8px'; const summary = document.getElementById('summary'); if (summary && summary.parentNode) summary.parentNode.insertBefore(theConsole, summary.nextSibling); else document.body.appendChild(theConsole); }
        // ensure a per-script card exists so the follow-up UI is available
        let sec = document.querySelector(`section.script-result[data-script="${data.script}"]`);
        if (!sec) {
          createOrUpdateEntry({ script: data.script, stdout: '', stderr: '', findings: [] });
          sec = document.querySelector(`section.script-result[data-script="${data.script}"]`);
        }
        if (sec) {
          let aiAnal = sec.querySelector('.ai-analysis'); if (!aiAnal) { aiAnal = document.createElement('div'); aiAnal.className='ai-analysis'; aiAnal.style.marginTop='8px'; aiAnal.style.background='#fff8f0'; aiAnal.style.padding='10px'; aiAnal.style.borderLeft='4px solid #ffc107'; sec.appendChild(aiAnal); }
          aiAnal.innerHTML = '<strong>AI SECURITY ANALYSIS (live):</strong><div style="margin-top:6px;white-space:pre-wrap;">' + (data.analysis || '') + '</div>';
          let rawEl = sec.querySelector('.ai-raw'); if (!rawEl) { rawEl = document.createElement('div'); rawEl.className='ai-raw'; rawEl.style.marginTop = '8px'; rawEl.style.background = '#f6f6f6'; rawEl.style.padding = '8px'; rawEl.style.borderLeft = '4px solid #ccc'; sec.appendChild(rawEl); }
          rawEl.textContent = data.raw || '';
          rawEl.style.display = (document.getElementById('show-llm-debug') && document.getElementById('show-llm-debug').checked && rawEl.textContent) ? 'block' : 'none';

          // create a per-script ai-console section (so users can ask follow-ups from the ai-console as well)
          try {
            const suggestion = (data.analysis || data.raw) ? `Based on the LLM analysis below, provide a concise remediation and one-sentence summary.` : '';
            ensureAiConsoleSection(data.script, suggestion);
          } catch (e) { console.error('ensureAiConsoleSection failed', e); }
        } else {
          const pre = document.createElement('pre'); pre.textContent = `[${data.script}] LLM RESULT:\n${data.analysis || ''}`; theConsole.appendChild(pre);
        }
      } else if (data.type === 'llm_error') {
        let theConsole = aiConsole || document.getElementById('ai-console');
        if (!theConsole) { theConsole = document.createElement('div'); theConsole.id='ai-console'; theConsole.style.marginTop='8px'; const summary = document.getElementById('summary'); if (summary && summary.parentNode) summary.parentNode.insertBefore(theConsole, summary.nextSibling); else document.body.appendChild(theConsole); }
        const pre = document.createElement('pre'); pre.textContent = `[${data.script}] LLM ERROR:\n${data.message || ''}`; pre.style.color = '#a00'; theConsole.appendChild(pre);
        const sec = document.querySelector(`section.script-result[data-script="${data.script}"]`);
        if (sec) {
          let aiAnal = sec.querySelector('.ai-analysis'); if (!aiAnal) { aiAnal = document.createElement('div'); aiAnal.className='ai-analysis'; aiAnal.style.marginTop='8px'; aiAnal.style.background='#fff8f0'; aiAnal.style.padding='10px'; aiAnal.style.borderLeft='4px solid #ffc107'; sec.appendChild(aiAnal); }
          aiAnal.innerHTML = '<strong style="color:#a00">LLM ERROR:</strong><div style="margin-top:6px;white-space:pre-wrap;color:#a00">' + (data.message || '') + '</div>';
        }
      }
    }

    function renderResults(data){ const sum=document.getElementById('summary'); const res=document.getElementById('results'); res.innerHTML=''; sum.innerHTML=''; if(data.summary && data.summary.length){ const ul=document.createElement('ul'); data.summary.forEach(s=>{const li=document.createElement('li'); li.textContent=s; ul.appendChild(li)}); sum.appendChild(ul);} else sum.textContent='No findings'; data.results.forEach(r=>{createOrUpdateEntry(r);}); }

    // Attach UI event handlers safely after DOM is ready and add LLM debug toggle
    document.addEventListener('DOMContentLoaded', ()=>{
      function attachSafe(id, event, handler){ const el = document.getElementById(id); if (el) el.addEventListener(event, handler); }
      attachSafe('run-selected', 'click', runSelected);
      attachSafe('run-level', 'click', runLevel);
      attachSafe('run-all', 'click', runAll);
      attachSafe('stop-all', 'click', async ()=>{ try { await fetch('?action=stop_all', { method: 'POST', credentials: 'same-origin' }); } catch(e){ console.error('stop request failed', e); } if (window.currentAbortController) window.currentAbortController.abort(); });
      attachSafe('select-all', 'click', ()=>{ document.querySelectorAll('#tests input[type=checkbox]').forEach(i=>i.checked=true); });
      attachSafe('clear-selection', 'click', ()=>{ document.querySelectorAll('#tests input[type=checkbox]').forEach(i=>i.checked=false); });

      // load tests into UI
      if (typeof loadScripts === 'function') { try { loadScripts(); } catch(e){ console.error('loadScripts failed', e); } }

      // global LLM question handler
      const askBtn = document.getElementById('ask-llm-global');
      if (askBtn) {
        askBtn.addEventListener('click', async function(){
          const qEl = document.getElementById('llm-global-question');
          const question = qEl && qEl.value && qEl.value.trim();
          if (!question) { alert('Enter a question'); return; }
          const respDivId = 'llm-global-response';
          let respDiv = document.getElementById(respDivId);
          if (!respDiv) { respDiv = document.createElement('div'); respDiv.id = respDivId; respDiv.style.marginTop='12px'; const controls = document.querySelector('.controls'); if (controls) controls.appendChild(respDiv); else document.body.appendChild(respDiv); }
          respDiv.innerHTML = '<em>Asking...</em>';
          try {
            const mode = (document.getElementById('llm-response-mode') && document.getElementById('llm-response-mode').value) || 'structured';
            const provider = document.getElementById('llm-provider')?.value || '';
            // Use summary text as assistant context when asking a global follow-up
            const summaryText = (document.getElementById('summary') && document.getElementById('summary').innerText) ? document.getElementById('summary').innerText.slice(0,2000) : '';
            const payload = { prompt: question, provider: provider, conversation: [{ role: 'assistant', content: summaryText }] };
            if (mode === 'structured') payload.system_prompt = FOLLOWUP_SYSTEM_PROMPT;
            const r = await fetch(LLM_SERVER_URL, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(payload) });
            if (!r.ok) {
              respDiv.innerHTML = `<span style="color:#a00">LLM request failed: ${r.status}</span>`;
              return;
            }
            const j = await r.json();
            const rawResp = j && typeof j.response !== 'undefined' ? String(j.response || '') : '';
            // reuse parsing helpers by attempting JSON parse; keep behavior compatible
            let display = '';
            try { const parsed = JSON.parse(rawResp); if (parsed && typeof parsed === 'object') {
              let parts = [];
              if (parsed.summary) parts.push('Summary: ' + parsed.summary);
              if (parsed.remediation) parts.push('Remediation: ' + (Array.isArray(parsed.remediation) ? parsed.remediation.join('; ') : parsed.remediation));
              if (parsed.notes) parts.push('Notes: ' + parsed.notes);
              if (parts.length) display = '<div style="white-space:pre-wrap;">' + parts.join('\n\n') + '</div>';
              else if (mode === 'structured') { const v = validateStructured(parsed); let warn=''; if (!v.ok) warn = `<div style=\"color:#a00;margin-bottom:8px\">Warning: structured response missing fields: ${v.missing.join(', ')}</div>`; display = warn + '<pre style="white-space:pre-wrap;">' + JSON.stringify(parsed, null, 2) + '</pre>'; }
              else display = '<pre style="white-space:pre-wrap;">' + JSON.stringify(parsed, null, 2) + '</pre>';
            } else { display = '<pre style="white-space:pre-wrap;">' + rawResp + '</pre>'; } } catch(e){ display = '<pre style="white-space:pre-wrap;">' + rawResp + '</pre>'; }

            respDiv.innerHTML = '<strong>LLM answer:</strong>' + display;
            if (rawResp) { const dbg = document.createElement('pre'); dbg.style.whiteSpace='pre-wrap'; dbg.textContent = rawResp; dbg.setAttribute('data-raw','1'); dbg.style.display = (document.getElementById('show-llm-debug') && document.getElementById('show-llm-debug').checked) ? 'block' : 'none'; respDiv.appendChild(dbg); }
          } catch (e) {
            respDiv.innerHTML = '<span style="color:#a00">Request failed: '+String(e)+'</span>';
          }
        });
      }

      // toggle showing LLM raw debug across UI
      const llmDebug = document.getElementById('show-llm-debug');
      if (llmDebug) llmDebug.addEventListener('change', (ev)=>{
        const show = !!ev.target.checked;
        document.querySelectorAll('.ai-raw').forEach(r=>{ r.style.display = (show && r.textContent) ? 'block' : 'none'; });
        // follow-up raw responses use <pre data-raw> appended to .followup-response
        document.querySelectorAll('.followup-response pre[data-raw]').forEach(p=>{ p.style.display = show ? 'block' : 'none'; });
      });

      async function checkLLMConnection() {
        const badge = document.getElementById('llm-status-badge');
        const dot = badge ? badge.querySelector('.pulse-dot') : null;
        const text = document.getElementById('llm-status-text');
        if (text) text.textContent = 'Connecting...';
        
        const url_ovr = document.getElementById('llm-url-override')?.value || '';
        const timeout_ovr = document.getElementById('llm-timeout-override')?.value || '15';
        const provider_ovr = document.getElementById('llm-provider')?.value || '';
        
        try {
          const query = new URLSearchParams({ action: 'test_llm' });
          if (url_ovr) query.append('url', url_ovr);
          query.append('timeout', timeout_ovr);
          query.append('provider', provider_ovr);
          
          const r = await fetch('?' + query.toString());
          const j = await r.json();
          const url_hint = j.url ? ` to ${j.url}` : '';
          const provider_hint = j.provider ? ` [${j.provider}]` : '';
          if (j.ok) {
            if (text) text.textContent = 'Connected' + provider_hint + (j.url ? ` (${j.url})` : '');
            if (dot) { dot.classList.add('online'); dot.classList.remove('offline'); }
            if (badge) { badge.style.color = '#28a745'; badge.style.background = '#e9f7ef'; }
          } else {
            const err_msg = j.llm && j.llm.error ? `: ${j.llm.error}` : (j.llm && j.llm.code ? ` (HTTP ${j.llm.code})` : '');
            if (text) text.textContent = 'Offline' + url_hint + err_msg;
            throw new Error('Offline');
          }
        } catch (e) {
          if (text && !text.textContent.includes('Offline')) {
            text.textContent = 'Connection Error: ' + e.message;
          }
          if (dot) { dot.classList.remove('online'); dot.classList.add('offline'); }
          if (badge) { badge.style.color = '#dc3545'; badge.style.background = '#fdedee'; }
        }
      }
      const testBtn = document.getElementById('btn-test-llm');
      if (testBtn) testBtn.addEventListener('click', checkLLMConnection);
      checkLLMConnection();
    });
