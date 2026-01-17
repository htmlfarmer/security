#!/usr/bin/env python3
"""Selenium-only speed analysis (enhanced).

Collects FCP, LCP, FP, TTFB, navigation timings, resource counts/transfer
size, layout-shift (CLS estimate), long-tasks and estimates TBT. Prints
simple recommendations based on thresholds.
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


def run(url, chrome_path=None, wait=8):
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
        # Allow time for late paints, LCP and observers to run
        time.sleep(wait)

        js = r"""
(function(){
  try{
    var r={fcp:null,fp:null,lcp:null,ttfb:null,navTiming:null,resources:{count:0,totalTransfer:0},longTasks:[],layoutShift:0};
    try{
      var nav = (performance.getEntriesByType && performance.getEntriesByType('navigation')||[])[0];
      if(nav){
        r.navTiming = {
          startTime: nav.startTime,
          ttfb: nav.responseStart? nav.responseStart - nav.startTime : null,
          dns: nav.domainLookupEnd && nav.domainLookupStart? nav.domainLookupEnd - nav.domainLookupStart : null,
          connect: nav.connectEnd && nav.connectStart? nav.connectEnd - nav.connectStart : null,
          request: nav.responseStart && nav.requestStart? nav.responseStart - nav.requestStart : null,
          response: nav.responseEnd && nav.responseStart? nav.responseEnd - nav.responseStart : null,
          domContentLoaded: nav.domContentLoadedEventEnd || null,
          loadEvent: nav.loadEventEnd || null
        };
        r.ttfb = r.navTiming.ttfb;
      } else if(performance.timing){ var t = performance.timing; r.ttfb = t.responseStart - t.requestStart; r.navTiming = {domContentLoaded:t.domContentLoadedEventEnd, loadEvent:t.loadEventEnd}; }
    }catch(e){}
    try{ (performance.getEntriesByType||(()=>[]))('paint').forEach(function(e){ if(e.name==='first-paint') r.fp=e.startTime; if(e.name==='first-contentful-paint') r.fcp=e.startTime; }); }catch(e){}
    try{ var lcps = (performance.getEntriesByType||(()=>[]))('largest-contentful-paint'); if(lcps.length) r.lcp = lcps[lcps.length-1].startTime || lcps[lcps.length-1].renderTime || null; }catch(e){}
    try{ var resources = (performance.getEntriesByType||(()=>[]))('resource')||[]; r.resources.count = resources.length; resources.forEach(function(res){ try{ r.resources.totalTransfer += res.transferSize||0 }catch(e){} }); }catch(e){}
    try{
      if(window.PerformanceObserver){
        var obs = new PerformanceObserver(function(list){ list.getEntries().forEach(function(e){ try{ if(e.entryType==='longtask') r.longTasks.push(e.duration); if(e.entryType==='layout-shift') r.layoutShift += e.value || 0; }catch(er){} }); });
        try{ obs.observe({type:'longtask', buffered:true}); }catch(e){}
        try{ obs.observe({type:'layout-shift', buffered:true}); }catch(e){}
        try{ obs.observe({type:'largest-contentful-paint', buffered:true}); }catch(e){}
        try{ obs.observe({type:'paint', buffered:true}); }catch(e){}
      } else {
        (performance.getEntriesByType||(()=>[]))('longtask').forEach(function(e){ r.longTasks.push(e.duration); });
        (performance.getEntriesByType||(()=>[]))('layout-shift').forEach(function(e){ r.layoutShift += e.value||0; });
      }
    }catch(e){}
    try{ window.__speedResults = r; }catch(e){}
    return r;
  }catch(e){ return {}; }
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
        print('URL:', url)
        print('First Contentful Paint:', human(res.get('fcp')))
        print('Largest Contentful Paint:', human(res.get('lcp')))
        print('First Paint:', human(res.get('fp')))
        print('Time To First Byte (TTFB):', human(res.get('ttfb') or (res.get('navTiming') and res.get('navTiming').get('ttfb'))))
        if res.get('navTiming'):
            nav = res.get('navTiming')
            if nav.get('domContentLoaded'):
                print('DOMContentLoaded:', human(nav.get('domContentLoaded')))
            if nav.get('loadEvent'):
                print('Load event:', human(nav.get('loadEvent')))
        print('Requests:', res.get('resources', {}).get('count'))
        total_transfer = res.get('resources', {}).get('totalTransfer') or 0
        try:
            print('Total transfer size:', f"{total_transfer/1024:.1f} KB" if total_transfer else 'n/a')
        except Exception:
            print('Total transfer size: n/a')
        print('Layout Shift (CLS estimate):', res.get('layoutShift'))
        print('Long tasks count:', len(long_tasks))
        print('Total Blocking Time (approx):', human(tbt))

        # Simple recommendations
        if res.get('lcp'):
            try:
                lcp = float(res.get('lcp'))
                if lcp <= 2500:
                    print('LCP: Good (<=2500ms)')
                elif lcp <= 4000:
                    print('LCP: Needs improvement (2500-4000ms)')
                else:
                    print('LCP: Poor (>4000ms)')
            except Exception:
                pass
        if tbt is not None:
            try:
                tbtv = float(tbt)
                if tbtv <= 200:
                    print('TBT: Good (<=200ms)')
                elif tbtv <= 600:
                    print('TBT: Needs improvement (200-600ms)')
                else:
                    print('TBT: Poor (>600ms)')
            except Exception:
                pass

    finally:
        try:
            driver.quit()
        except Exception:
            pass


def main():
    p = argparse.ArgumentParser()
    p.add_argument('url')
    p.add_argument('--chrome-path')
    p.add_argument('--wait', type=int, default=8)
    args = p.parse_args()
    try:
        run(args.url, chrome_path=args.chrome_path, wait=args.wait)
    except Exception as e:
        print('Error:', e, file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
#!/usr/bin/env python3
"""Selenium-only speed analysis (enhanced).

Collects FCP, LCP, FP, TTFB, navigation timings, resource counts/transfer
size, layout-shift (CLS estimate), long-tasks and estimates TBT. Prints
simple recommendations based on thresholds.
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


def run(url, chrome_path=None, wait=8):
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
        # Allow time for late paints, LCP and observers to run
        time.sleep(wait)

        js = r"""
(function(){
  try{
    var r={fcp:null,fp:null,lcp:null,ttfb:null,navTiming:null,resources:{count:0,totalTransfer:0},longTasks:[],layoutShift:0};
    try{
      var nav = (performance.getEntriesByType && performance.getEntriesByType('navigation')||[])[0];
      if(nav){
        r.navTiming = {
          startTime: nav.startTime,
          ttfb: nav.responseStart? nav.responseStart - nav.startTime : null,
          dns: nav.domainLookupEnd && nav.domainLookupStart? nav.domainLookupEnd - nav.domainLookupStart : null,
          connect: nav.connectEnd && nav.connectStart? nav.connectEnd - nav.connectStart : null,
          request: nav.responseStart && nav.requestStart? nav.responseStart - nav.requestStart : null,
          response: nav.responseEnd && nav.responseStart? nav.responseEnd - nav.responseStart : null,
          domContentLoaded: nav.domContentLoadedEventEnd || null,
          loadEvent: nav.loadEventEnd || null
        };
        r.ttfb = r.navTiming.ttfb;
      } else if(performance.timing){ var t = performance.timing; r.ttfb = t.responseStart - t.requestStart; r.navTiming = {domContentLoaded:t.domContentLoadedEventEnd, loadEvent:t.loadEventEnd}; }
    }catch(e){}
    try{ (performance.getEntriesByType||(()=>[]))('paint').forEach(function(e){ if(e.name==='first-paint') r.fp=e.startTime; if(e.name==='first-contentful-paint') r.fcp=e.startTime; }); }catch(e){}
    try{ var lcps = (performance.getEntriesByType||(()=>[]))('largest-contentful-paint'); if(lcps.length) r.lcp = lcps[lcps.length-1].startTime || lcps[lcps.length-1].renderTime || null; }catch(e){}
    try{ var resources = (performance.getEntriesByType||(()=>[]))('resource')||[]; r.resources.count = resources.length; resources.forEach(function(res){ try{ r.resources.totalTransfer += res.transferSize||0 }catch(e){} }); }catch(e){}
    try{
      if(window.PerformanceObserver){
        var obs = new PerformanceObserver(function(list){ list.getEntries().forEach(function(e){ try{ if(e.entryType==='longtask') r.longTasks.push(e.duration); if(e.entryType==='layout-shift') r.layoutShift += e.value || 0; }catch(er){} }); });
        try{ obs.observe({type:'longtask', buffered:true}); }catch(e){}
        try{ obs.observe({type:'layout-shift', buffered:true}); }catch(e){}
        try{ obs.observe({type:'largest-contentful-paint', buffered:true}); }catch(e){}
        try{ obs.observe({type:'paint', buffered:true}); }catch(e){}
      } else {
        (performance.getEntriesByType||(()=>[]))('longtask').forEach(function(e){ r.longTasks.push(e.duration); });
        (performance.getEntriesByType||(()=>[]))('layout-shift').forEach(function(e){ r.layoutShift += e.value||0; });
      }
    }catch(e){}
    try{ window.__speedResults = r; }catch(e){}
    return r;
  }catch(e){ return {}; }
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
        print('URL:', url)
        print('First Contentful Paint:', human(res.get('fcp')))
        print('Largest Contentful Paint:', human(res.get('lcp')))
        print('First Paint:', human(res.get('fp')))
        print('Time To First Byte (TTFB):', human(res.get('ttfb') or (res.get('navTiming') and res.get('navTiming').get('ttfb'))))
        if res.get('navTiming'):
            nav = res.get('navTiming')
            if nav.get('domContentLoaded'):
                print('DOMContentLoaded:', human(nav.get('domContentLoaded')))
            if nav.get('loadEvent'):
                print('Load event:', human(nav.get('loadEvent')))
        print('Requests:', res.get('resources', {}).get('count'))
        total_transfer = res.get('resources', {}).get('totalTransfer') or 0
        try:
            print('Total transfer size:', f"{total_transfer/1024:.1f} KB" if total_transfer else 'n/a')
        except Exception:
            print('Total transfer size: n/a')
        print('Layout Shift (CLS estimate):', res.get('layoutShift'))
        print('Long tasks count:', len(long_tasks))
        print('Total Blocking Time (approx):', human(tbt))

        # Simple recommendations
        if res.get('lcp'):
            try:
                lcp = float(res.get('lcp'))
                if lcp <= 2500:
                    print('LCP: Good (<=2500ms)')
                elif lcp <= 4000:
                    print('LCP: Needs improvement (2500-4000ms)')
                else:
                    print('LCP: Poor (>4000ms)')
            except Exception:
                pass
        if tbt is not None:
            try:
                tbtv = float(tbt)
                if tbtv <= 200:
                    print('TBT: Good (<=200ms)')
                elif tbtv <= 600:
                    print('TBT: Needs improvement (200-600ms)')
                else:
                    print('TBT: Poor (>600ms)')
            except Exception:
                pass

    finally:
        try:
            driver.quit()
        except Exception:
            pass


def main():
    p = argparse.ArgumentParser()
    p.add_argument('url')
    p.add_argument('--chrome-path')
    p.add_argument('--wait', type=int, default=8)
    args = p.parse_args()
    try:
        run(args.url, chrome_path=args.chrome_path, wait=args.wait)
    except Exception as e:
        print('Error:', e, file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
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
                    try{
                        var r={fcp:null,fp:null,lcp:null,ttfb:null,navTiming:null,resources:{count:0,totalTransfer:0},longTasks:[],layoutShift:0};
                        try{
                            var nav = (performance.getEntriesByType && performance.getEntriesByType('navigation')||[])[0];
                            if(nav){
                                r.navTiming = {
                                    startTime: nav.startTime,
                                    ttfb: nav.responseStart? nav.responseStart - nav.startTime : null,
                                    dns: nav.domainLookupEnd && nav.domainLookupStart? nav.domainLookupEnd - nav.domainLookupStart : null,
                                    connect: nav.connectEnd && nav.connectStart? nav.connectEnd - nav.connectStart : null,
                                    request: nav.responseStart && nav.requestStart? nav.responseStart - nav.requestStart : null,
                                    response: nav.responseEnd && nav.responseStart? nav.responseEnd - nav.responseStart : null,
                                    domContentLoaded: nav.domContentLoadedEventEnd || null,
                                    loadEvent: nav.loadEventEnd || null
                                };
                                r.ttfb = r.navTiming.ttfb;
                            } else if(performance.timing){ var t = performance.timing; r.ttfb = t.responseStart - t.requestStart; r.navTiming = {domContentLoaded:t.domContentLoadedEventEnd, loadEvent:t.loadEventEnd}; }
                        }catch(e){}
                        try{ (performance.getEntriesByType||(()=>[]))('paint').forEach(function(e){ if(e.name==='first-paint') r.fp=e.startTime; if(e.name==='first-contentful-paint') r.fcp=e.startTime; }); }catch(e){}
                        try{ var lcps = (performance.getEntriesByType||(()=>[]))('largest-contentful-paint'); if(lcps.length) r.lcp = lcps[lcps.length-1].startTime || lcps[lcps.length-1].renderTime || null; }catch(e){}
                        try{ var resources = (performance.getEntriesByType||(()=>[]))('resource')||[]; r.resources.count = resources.length; resources.forEach(function(res){ try{ r.resources.totalTransfer += res.transferSize||0 }catch(e){} }); }catch(e){}
                        try{
                            if(window.PerformanceObserver){
                                var obs = new PerformanceObserver(function(list){ list.getEntries().forEach(function(e){ try{ if(e.entryType==='longtask') r.longTasks.push(e.duration); if(e.entryType==='layout-shift') r.layoutShift += e.value || 0; }catch(er){} }); });
                                try{ obs.observe({type:'longtask', buffered:true}); }catch(e){}
                                try{ obs.observe({type:'layout-shift', buffered:true}); }catch(e){}
                                try{ obs.observe({type:'largest-contentful-paint', buffered:true}); }catch(e){}
                                try{ obs.observe({type:'paint', buffered:true}); }catch(e){}
                            } else { (performance.getEntriesByType||(()=>[]))('longtask').forEach(function(e){ r.longTasks.push(e.duration); }); (performance.getEntriesByType||(()=>[]))('layout-shift').forEach(function(e){ r.layoutShift += e.value||0; }); }
                        }catch(e){}
                        try{ window.__speedResults = r; }catch(e){}
                        return r;
                    }catch(e){ return {}; }
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
        print('First Paint:', human(res.get('fp')))
        print('Time To First Byte (TTFB):', human(res.get('ttfb') or (res.get('navTiming') and res.get('navTiming').get('ttfb'))))
        if res.get('navTiming'):
            nav = res.get('navTiming')
            if nav.get('domContentLoaded'):
                print('DOMContentLoaded:', human(nav.get('domContentLoaded')))
            if nav.get('loadEvent'):
                print('Load event:', human(nav.get('loadEvent')))
        print('Requests:', res.get('resources', {}).get('count'))
        total_transfer = res.get('resources', {}).get('totalTransfer') or 0
        try:
            print('Total transfer size:', f"{total_transfer/1024:.1f} KB" if total_transfer else 'n/a')
        except Exception:
            print('Total transfer size: n/a')
        print('Layout Shift (CLS estimate):', res.get('layoutShift'))
        print('Long tasks count:', len(long_tasks))
        print('Total Blocking Time (approx):', human(tbt))

        # Simple recommendations
        if res.get('lcp'):
            lcp = float(res.get('lcp'))
            if lcp <= 2500:
                print('LCP: Good (<=2500ms)')
            elif lcp <= 4000:
                print('LCP: Needs improvement (2500-4000ms)')
            else:
                print('LCP: Poor (>4000ms)')
        if tbt is not None:
            if tbt <= 200:
                print('TBT: Good (<=200ms)')
            elif tbt <= 600:
                print('TBT: Needs improvement (200-600ms)')
            else:
                print('TBT: Poor (>600ms)')

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
