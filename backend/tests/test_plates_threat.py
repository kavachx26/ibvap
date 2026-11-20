"""Unit tests: plate cleaning, repair, format validation, watchlist matching,
and the threat score."""
import time

from app.core import plates
from app.core.threat import level_for


def test_clean_and_format():
    assert plates.clean("wb-74 ak 2231") == "WB74AK2231"
    assert plates.is_valid_format("WB74AK2231")
    assert plates.is_valid_format("21BH4521KX")
    assert not plates.is_valid_format("XX74AK2231")      # not a state code
    assert not plates.is_valid_format("WB74AK22")


def test_positional_repair():
    assert plates.repair("W874AK223I") == "WB74AK2231"   # 8->B in state code, I->1 in last four
    assert plates.repair("0L1CN4S21") == "DL1CN4521" or plates.repair("0L1CN4S21") == "OL1CN4521"


def test_watchlist_match_types():
    wl = ["WB74AK2231", "AS01BC9087"]
    assert plates.match_watchlist("WB74AK2231", wl) == ("WB74AK2231", "exact")
    assert plates.match_watchlist("WB74AK223I", wl) == ("WB74AK2231", "lookalike")
    assert plates.match_watchlist("WB74AK2281", wl) == ("WB74AK2231", "one_char")
    assert plates.match_watchlist("KA05MN7788", wl) is None
    assert plates.match_watchlist("AB", wl) is None


def test_threat_levels():
    assert level_for(0) == "LOW"
    assert level_for(25) == "GUARDED"
    assert level_for(50) == "ELEVATED"
    assert level_for(90) == "CRITICAL"


def test_scenarios_fire_every_alert_type():
    from app.core.storage import init_db
    from app.core.pipeline import CameraSession
    init_db()
    seen = set()
    for cam, sc in (("t-01", "fence"), ("t-02", "checkpost"), ("t-03", "river"), ("t-04", "road")):
        s = CameraSession(cam, scenario=sc)
        for _ in range(840):
            _, _, alerts = s.step_simulation()
            seen |= {a.alert_type for a in alerts}
    assert {"loitering", "unauthorized_crossing", "group_formation", "erratic_motion",
            "night_time_movement", "watchlist_match"} <= seen
