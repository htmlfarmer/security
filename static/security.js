async function loadScripts() {
  const r = await fetch('/security.php?action=scripts');
  const data = await r.json();
  const container = document.getElementById('tests');
  container.innerHTML = '';

  data.scripts.forEach(s => {
    const id = `chk_${s}`;
    const label = document.createElement('label');
    label.innerHTML = `<input type="checkbox" id="${id}" value="${s}"> ${s}`;
    container.appendChild(label);
  });
}

async function runSelected() {
  const url = document.getElementById('url').value;
  const checks = Array.from(document.querySelectorAll('#tests input:checked')).map(i => i.value);
  await run(url, {tests: checks});
}

async function runLevel() {
  const url = document.getElementById('url').value;
  const level = document.getElementById('level').value;
  await run(url, {level});
}

async function runAll() {
  const url = document.getElementById('url').value;
  // fetch all available scripts from server and run them
  const r = await fetch('/security.php?action=scripts');
  const data = await r.json();
  await run(url, {tests: data.scripts});
}

async function run(url, payload) {
  if (!url) {
    alert('Enter a target URL');
    return;
  }
  payload.url = url;
  const resDiv = document.getElementById('results');
  const sumDiv = document.getElementById('summary');
  resDiv.innerHTML = '<em>Running...</em>';
  sumDiv.innerHTML = '';

  const resp = await fetch('/security.php', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload)
  });

  const data = await resp.json();
  if (data.error) {
    resDiv.innerText = data.error;
    return;
  }

  // summary
  sumDiv.innerHTML = '';
  if (data.summary && data.summary.length) {
    const ul = document.createElement('ul');
    data.summary.forEach(s => {
      const li = document.createElement('li'); li.textContent = s; ul.appendChild(li);
    });
    sumDiv.appendChild(ul);
  } else {
    sumDiv.textContent = 'No findings';
  }

  // detailed per-script
  resDiv.innerHTML = '';
  data.results.forEach(r => {
    const section = document.createElement('section');
    section.className = 'script-result';
    const h = document.createElement('h4'); h.textContent = r.script; section.appendChild(h);

    const preOut = document.createElement('pre');
    preOut.textContent = r.stdout || '';
    section.appendChild(preOut);

    if (r.stderr) {
      const preErr = document.createElement('pre');
      preErr.className = 'stderr';
      preErr.textContent = r.stderr;
      section.appendChild(preErr);
    }

    if (r.findings && r.findings.length) {
      const f = document.createElement('div');
      f.className = 'findings';
      f.innerHTML = '<strong>Findings:</strong><ul>' + r.findings.map(x => `<li>${x}</li>`).join('') + '</ul>';
      section.appendChild(f);
    }

    resDiv.appendChild(section);
  });
}

document.getElementById('run-selected').addEventListener('click', runSelected);
document.getElementById('run-level').addEventListener('click', runLevel);
document.getElementById('run-all').addEventListener('click', runAll);

loadScripts();
