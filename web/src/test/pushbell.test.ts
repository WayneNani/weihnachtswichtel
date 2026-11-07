import assert from "node:assert/strict";
import { test } from "node:test";
import { bellLook } from "../ui/pushbell";

test("bell: attention label and dot until opened once", () => {
  const first = bellLook({ support: "supported", enabled: false, prompted: false });
  assert.equal(first.visible, true);
  assert.equal(first.variant, "off");
  assert.equal(first.label, "Benachrichtigen?");
  assert.equal(first.dot, true);

  const later = bellLook({ support: "supported", enabled: false, prompted: true });
  assert.equal(later.label, null);
  assert.equal(later.dot, false);
  assert.match(later.ariaLabel, /ausgeschaltet/);
});

test("bell: switched on shows no attention", () => {
  for (const prompted of [false, true]) {
    const on = bellLook({ support: "supported", enabled: true, prompted });
    assert.deepEqual([on.visible, on.variant, on.label, on.dot], [true, "on", null, false]);
  }
});

test("bell: iOS outside home screen still invites (panel explains the extra step)", () => {
  const ios = bellLook({ support: "ios_homescreen", enabled: false, prompted: false });
  assert.equal(ios.visible, true);
  assert.equal(ios.dot, true);
});

test("bell: blocked is visible without attention, unsupported is hidden", () => {
  const denied = bellLook({ support: "denied", enabled: false, prompted: false });
  assert.deepEqual([denied.visible, denied.variant, denied.dot, denied.label], [true, "blocked", false, null]);
  assert.equal(bellLook({ support: "unsupported", enabled: false, prompted: false }).visible, false);
  assert.equal(bellLook({ support: "insecure", enabled: false, prompted: false }).visible, false);
});
