#!/usr/bin/env python3
"""Selenium-only speed analysis.

Collects FCP, LCP and estimates TBT using Performance API.
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
