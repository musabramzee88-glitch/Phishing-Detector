"use strict";
const test = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");

test("service worker prunes older fingerprints of the same file", () => {
    const sw = fs.readFileSync(path.join(__dirname, "..", "public", "sw.js"), "utf8");
    assert.match(sw, /cache\.keys\(\)/);
    assert.match(sw, /u\.pathname === url\.pathname && u\.search !== url\.search/);
});

test("inspector caps snapshot memory by count and total bytes", () => {
    const src = fs.readFileSync(path.join(__dirname, "..", "server", "inspect.js"), "utf8");
    assert.match(src, /MAX_SNAPSHOT_BYTES = 40 \* 1024 \* 1024/);
    assert.match(src, /snapshotBytes \+ htmlDoc\.length > MAX_SNAPSHOT_BYTES/);
});
