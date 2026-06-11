"""Capture README screenshots from a running dashboard (localhost:8511).

Drives the app with Selenium so tabs, scrolling, and the incident-report
generation can all be captured. Run with the dashboard already up:

    streamlit run dashboard.py --server.port 8511 &
    python scripts/capture_screenshots.py
"""
import os
import sys
import time

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

BASE = "http://localhost:8511"
OUT = "docs"


def make_driver(width=1440, height=1100):
    opts = Options()
    opts.add_argument("--headless=new")
    opts.add_argument(f"--window-size={width},{height}")
    opts.add_argument("--use-angle=swiftshader")
    opts.add_argument("--enable-unsafe-swiftshader")
    opts.add_argument("--hide-scrollbars")
    driver = webdriver.Chrome(options=opts)
    driver.set_script_timeout(60)
    return driver


def wait_ready(d, timeout=300):
    """Wait until the app has rendered and is (probably) done running."""
    start = time.time()
    rendered_at = None
    while time.time() - start < timeout:
        exc = d.find_elements(By.CSS_SELECTOR, '[data-testid="stException"]')
        if exc:
            raise RuntimeError("app exception: " + exc[0].text[:300])
        metrics = d.find_elements(By.CSS_SELECTOR, '[data-testid="stMetric"]')
        running = d.find_elements(By.CSS_SELECTOR, '[data-testid="stStatusWidget"]')
        if metrics:
            rendered_at = rendered_at or time.time()
            # done running, or rendered and stable for a grace period
            if not running or time.time() - rendered_at > 45:
                time.sleep(2)
                return
        time.sleep(1.5)
    raise RuntimeError("timed out waiting for app to render")


def click_tab(d, label):
    for b in d.find_elements(By.CSS_SELECTOR, 'button[role="tab"]'):
        if label.lower() in b.text.lower():
            d.execute_script("arguments[0].scrollIntoView({block:'center'});", b)
            time.sleep(0.5)
            d.execute_script("arguments[0].click();", b)
            time.sleep(2.5)
            return
    raise RuntimeError(f"tab not found: {label}")


def scroll_to_text(d, text, offset=-60):
    last_err = None
    for _ in range(4):
        try:
            el = d.find_element(By.XPATH, f"//*[contains(text(), {text!r})]")
            d.execute_script("arguments[0].scrollIntoView({block:'start'});", el)
            d.execute_script(
                f"var m=document.querySelector('[data-testid=\"stMain\"]');"
                f"if(m) m.scrollBy(0,{offset}); window.scrollBy(0,{offset});")
            time.sleep(1.2)
            return
        except Exception as e:  # transient while the app reruns
            last_err = e
            time.sleep(2.5)
    raise last_err


def shot(d, name):
    path = os.path.join(OUT, name)
    d.save_screenshot(path)
    print(f"  saved {path}")


def main():
    os.makedirs(OUT, exist_ok=True)

    if "--skip-sample" not in sys.argv:
        print("sample dataset views...")
        d = make_driver(1440, 1150)
        d.get(BASE)
        wait_ready(d)
        shot(d, "dashboard_hero.png")
        scroll_to_text(d, "Case management")
        shot(d, "dashboard_case.png")
        d.set_window_size(1440, 2900)
        d.get(BASE)
        wait_ready(d)
        shot(d, "dashboard.png")
        d.quit()

    print("benchmark overview + map...")
    d = make_driver(1440, 1060)
    d.get(BASE + "/?dataset=benchmark")
    wait_ready(d)
    shot(d, "dashboard_benchmark.png")
    scroll_to_text(d, "Attack origins")
    shot(d, "dashboard_map.png")

    print("queue tab...")
    scroll_to_text(d, "Analyst queue")
    shot(d, "dashboard_queue.png")

    print("threat analysis sections...")
    click_tab(d, "Threat analysis")
    scroll_to_text(d, "Attack timeline")
    shot(d, "dashboard_timeline.png")
    scroll_to_text(d, "MITRE ATT&CK coverage")
    shot(d, "dashboard_attack_matrix.png")
    scroll_to_text(d, "Most targeted accounts")
    shot(d, "dashboard_entities.png")

    print("incident report (calls Claude, ~30-60s)...")
    scroll_to_text(d, "Incident report")
    for b in d.find_elements(By.TAG_NAME, "button"):
        if "Generate with Claude" in b.text:
            b.click()
            break
    end = time.time() + 120
    while time.time() < end:
        if "Executive" in d.find_element(By.TAG_NAME, "body").text:
            break
        time.sleep(3)
    time.sleep(2)
    scroll_to_text(d, "Incident report")
    d.set_window_size(1440, 1500)
    time.sleep(1)
    scroll_to_text(d, "Incident report")
    shot(d, "dashboard_report.png")

    print("evaluation tab...")
    d.set_window_size(1440, 1060)
    click_tab(d, "Evaluation")
    scroll_to_text(d, "verdicts match")
    shot(d, "dashboard_eval.png")
    d.quit()
    print("done")


if __name__ == "__main__":
    sys.exit(main())
