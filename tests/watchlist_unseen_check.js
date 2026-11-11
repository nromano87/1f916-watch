/**
 * New-inbox must not treat the whole id window as new when the newest
 * rows were already acknowledged (the usual case after opening your page).
 */
const assert = require("assert");
const fs = require("fs");
const path = require("path");

const store = {};
global.localStorage = {
  getItem(k) {
    return Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null;
  },
  setItem(k, v) {
    store[k] = String(v);
  },
  removeItem(k) {
    delete store[k];
  },
};
global.document = {
  readyState: "complete",
  getElementById() {
    return null;
  },
  querySelector() {
    return null;
  },
  querySelectorAll() {
    return [];
  },
  addEventListener() {},
  createElement() {
    return {
      id: "",
      className: "",
      style: {},
      dataset: {},
      classList: { add() {}, toggle() {}, remove() {} },
      setAttribute() {},
      appendChild() {},
      insertBefore() {},
    };
  },
  head: { appendChild() {} },
};
global.window = global;
global.location = { pathname: "/watchlist", replace() {} };
global.fetch = () => Promise.resolve({ ok: false });

const src = fs.readFileSync(
  path.join(__dirname, "../src/f916_agent/watchlist.js"),
  "utf8"
);
eval(src);
const wl = global.f916Watchlist;
assert.ok(wl && wl.unseenCount, "watchlist api missing");

const handle = "cursor-grok";
// Previously acknowledged only the two newest preview rows.
localStorage.setItem(
  "f916-watchlist-seen",
  JSON.stringify({ [handle]: ["c:109", "c:108"] })
);
const ids = ["c:109", "c:108", "c:107", "c:106", "c:105"];
const ats = {
  "c:109": 5000,
  "c:108": 4000,
  "c:107": 3000,
  "c:106": 2000,
  "c:105": 1000,
};
assert.strictEqual(
  wl.unseenCount(handle, ids, ats),
  0,
  "older ids in the window are not new"
);

ids.unshift("c:110");
ats["c:110"] = 6000;
assert.strictEqual(
  wl.unseenCount(handle, ids, ats),
  1,
  "mail newer than the watermark counts"
);

// Opening the citizen page acknowledges its inbox and must not shrink seen.
wl.markSeen(handle, ["c:110"], { "c:110": 6000 });
assert.strictEqual(wl.unseenCount(handle, ids, ats), 0);

// An empty mark must not wipe the baseline back to "everything is new".
wl.markSeen(handle, []);
assert.strictEqual(wl.unseenCount(handle, ids, ats), 0);

// Empty stored baseline re-primes instead of reporting the whole window.
localStorage.setItem(
  "f916-watchlist-seen",
  JSON.stringify({ [handle]: [] })
);
assert.strictEqual(wl.unseenCount(handle, ids, ats), 0);
assert.strictEqual(wl.unseenCount(handle, ids.concat(["c:111"]), Object.assign({ "c:111": 7000 }, ats)), 1);

console.log("watchlist unseen ok");
process.exit(0);
