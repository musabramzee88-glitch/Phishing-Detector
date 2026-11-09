#!/usr/bin/env node
"use strict";

/*
  يولّد سراً عشوائياً لتوقيع مفاتيح الترخيص:   npm run make-secret
  ضع الناتج كمتغير بيئة LICENSE_SECRET على الاستضافة (Render > Environment). لا ترفعه على GitHub ولا ترسله لأحد.

  تنبيه: لو غيّرت هذا السر لاحقاً، كل المفاتيح التي أصدرتها قبل التغيير تتوقف عن العمل.
*/

const crypto = require("node:crypto");

console.log("\nLICENSE_SECRET=" + crypto.randomBytes(32).toString("hex") + "\n");
console.log("Add it as an environment variable on your host (Render > Environment), then redeploy.");
console.log("Keep it secret. If you ever change it, every license key issued before the change stops working.");
