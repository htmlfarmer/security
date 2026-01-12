#!/usr/bin/env python3
"""Minimal Selenium-only speed analysis.

This lightweight script navigates to a URL with Selenium and queries
the Performance API to return FCP, LCP and an estimated TBT.
"""

import argparse
import sys
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options


def human(ms):
    if ms is None:
        return "n/a"
    try:
        ms = float(ms)
    except Exception:
        return "n/a"
    if ms >= 1000:
        return f"{ms/1000:.2f} s"
    return f"{ms:.0f} ms"


def run(url, chrome_path=None, wait=5):
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    if chrome_path:
        opts.binary_location = chrome_path

    driver = webdriver.Chrome(options=opts)
    try:
        driver.set_page_load_timeout(wait + 30)
        driver.get(url)
        time.sleep(wait)

        js = r"""
        (function(){
          var r={fcp:null,lcp:null,longTasks:[]};
          try{ (performance.getEntriesByType||(()=>[]))('paint').forEach(function(e){ if(e.name==='first-contentful-paint') r.fcp=e.startTime; }); }catch(e){}
          try{ (performance.getEntriesByType||(()=>[]))('largest-contentful-paint').forEach(function(e){ r.lcp=e.startTime||e.renderTime||r.lcp; }); }catch(e){}
          try{
            if(window.PerformanceObserver){
              var obs = new PerformanceObserver(function(list){ list.getEntries().forEach(function(e){ if(e.entryType==='longtask') r.longTasks.push(e.duration); }); });
              try{ obs.observe({type:'longtask', buffered:true}); }catch(e){}
            } else {
              (performance.getEntriesByType||(()=>[]))('longtask').forEach(function(e){ r.longTasks.push(e.duration); });
            }
          }catch(e){}
          return r;
        })();
        """

        res = driver.execute_script(js) or {}
        long_tasks = res.get('longTasks') or []
        tbt = None
        if long_tasks:
            try:
                tbt = sum(max(0, float(d)-50.0) for d in long_tasks)
            except Exception:
                tbt = None

        print('\nSpeed Analysis Report')
        print('---------------------')
        print('First Contentful Paint:', human(res.get('fcp')))
        print('Largest Contentful Paint:', human(res.get('lcp')))
        print('Total Blocking Time (approx):', human(tbt))

    finally:
        try:
            driver.quit()
        except Exception:
            pass


def main():
    p = argparse.ArgumentParser()
    p.add_argument('url')
    p.add_argument('--chrome-path')
    p.add_argument('--wait', type=int, default=5)
    args = p.parse_args()
    try:
        run(args.url, chrome_path=args.chrome_path, wait=args.wait)
    except Exception as e:
        print('Error:', e, file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""Website speed analysis (Selenium default, optional Lighthouse).

Collects FCP, LCP and estimates TBT. Defaults to Selenium; pass
`--use-lighthouse` to run Lighthouse via `npx` if available.
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

try:
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
except Exception:
    webdriver = None


def human(ms: float) -> str:
    if ms is None:
        return "n/a"
    try:
        ms = float(ms)
    except Exception:
        return "n/a"
    if ms >= 1000:
        return f"{ms/1000:.2f} s"
    return f"{ms:.0f} ms"


def evaluate_score(score: float) -> str:
    if score is None:
        return "n/a"
    try:
        s = float(score)
    except Exception:
        return "n/a"
    if s >= 0.9:
        return "Good"
    if s >= 0.5:
        return "Needs Improvement"
    return "Poor"


def run_lighthouse(url: str, chrome_path: str = None, timeout: int = 120):
    npx = shutil.which("npx")
    if not npx:
        raise FileNotFoundError("npx not found on PATH; install Node.js and npm")

    with tempfile.NamedTemporaryFile(suffix=".report.json", delete=False) as tmp:
        out_path = tmp.name

    cmd = [
        npx,
        "lighthouse",
        url,
        "--quiet",
        "--output=json",
        f"--output-path={out_path}",
        "--only-categories=performance",
        "--chrome-flags=--headless --no-sandbox --disable-gpu",
    ]
    if chrome_path:
        cmd.append(f"--chrome-path={chrome_path}")

    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"Lighthouse failed: {proc.stderr.strip()[:1000]}")

    data = json.loads(Path(out_path).read_text())

    def get(name):
        try:
            return data["audits"][name]["numericValue"]
        except Exception:
            return None

    metrics = {
        "first-contentful-paint": get("first-contentful-paint"),
        "largest-contentful-paint": get("largest-contentful-paint"),
        "total-blocking-time": get("total-blocking-time"),
        "speed-index": get("speed-index"),
        "performance_score": data.get("categories", {}).get("performance", {}).get("score"),
    }

    return metrics


def selenium_fallback(url: str, headless: bool = True, wait: int = 8, chrome_path: str = None):
    if webdriver is None:
        raise RuntimeError("Selenium not installed in this environment")

    opts = Options()
    if headless:
        opts.add_argument("--headless=new")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    if chrome_path:
        opts.binary_location = chrome_path

    driver = webdriver.Chrome(options=opts)
    try:
        driver.set_page_load_timeout(wait + 30)
        driver.get(url)
        time.sleep(wait)

        js = r"""
        (function(){
          try{ if(window.__speedResults) return window.__speedResults; }catch(e){}
          var results = {fcp:null, lcp:null, longTasks:[]};
          try{
            var paints = (performance.getEntriesByType && performance.getEntriesByType('paint')) || [];
            for(var i=0;i<paints.length;i++){ if(paints[i].name==='first-contentful-paint') results.fcp = paints[i].startTime; }
          }catch(e){}
          try{
            var lcps = (performance.getEntriesByType && performance.getEntriesByType('largest-contentful-paint')) || [];
            if(lcps.length) results.lcp = lcps[lcps.length-1].startTime || lcps[lcps.length-1].renderTime || null;
          }catch(e){}
          try{
            if(window.PerformanceObserver){
              var obs = new PerformanceObserver(function(list){
                list.getEntries().forEach(function(e){
        try:
            driver.quit()
        except Exception:
            pass
                                });
                            });
                            try{ obs.observe({type:'longtask', buffered:true}); }catch(_){}
                            try{ obs.observe({type:'largest-contentful-paint', buffered:true}); }catch(_){}
                            try{ obs.observe({type:'paint', buffered:true}); }catch(_){}
                        } else {
                            var lts = performance.getEntriesByType && performance.getEntriesByType('longtask') || [];
                            for(var j=0;j<lts.length;j++) results.longTasks.push(lts[j].duration);
                        }
                    }catch(e){}
                    try{ window.__speedResults = results; }catch(e){}
                    return results;
                })();
                """

                results = driver.execute_script(js)
                if not results:
                        results = {}

                long_tasks = results.get("longTasks") or []
                tbt = None
                if long_tasks:
                        try:
                                tbt = sum(max(0, float(d) - 50.0) for d in long_tasks)
                        except Exception:
                                tbt = None

                metrics = {
                        "first-contentful-paint": results.get("fcp") if isinstance(results.get("fcp"), (int, float)) else None,
                        "largest-contentful-paint": results.get("lcp") if isinstance(results.get("lcp"), (int, float)) else None,
                        "total-blocking-time": tbt,
                        "speed-index": None,
                        "performance_score": None,
                }
        return metrics
    finally:
        try:
            driver.quit()
        except Exception:
            pass


def print_report(metrics: dict):
    fcp = metrics.get("first-contentful-paint")
    lcp = metrics.get("largest-contentful-paint")
    tbt = metrics.get("total-blocking-time")
    si = metrics.get("speed-index")
    score = metrics.get("performance_score")

    print("\nSpeed Analysis Report")
    print("---------------------")
    print(f"First Contentful Paint: {human(fcp)}")
    print(f"Largest Contentful Paint: {human(lcp)}")
    print(f"Total Blocking Time (approx): {human(tbt)}")
    print(f"Speed Index: {human(si)}")
    if score is not None:
        print(f"Performance score: {score*100:.0f}/100 — {evaluate_score(score)}")
    else:
        print("Performance score: n/a")


def main():
    p = argparse.ArgumentParser(description="Website speed analysis (Lighthouse + Selenium fallback)")
    p.add_argument("url")
    p.add_argument("--chrome-path", help="Path to Chrome/Chromium binary")
    p.add_argument("--use-lighthouse", action="store_true", help="Use Lighthouse via npx instead of Selenium (default: Selenium)")
    p.add_argument("--wait", type=int, default=5, help="Seconds to wait after load when using Selenium")
    args = p.parse_args()

    try:
        if args.use_lighthouse:
            metrics = run_lighthouse(args.url, chrome_path=args.chrome_path)
        else:
            metrics = selenium_fallback(args.url, wait=args.wait, chrome_path=args.chrome_path)

        print_report(metrics)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
