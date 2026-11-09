#!/usr/bin/env node
"use strict";

/*
  يولّد حساب أدمن جديد: node tools/make-admin.js <username>   (أو: npm run make-admin -- <username>)

  - كلمة السر تُكتب هنا على جهازك فقط (لا تظهر على الشاشة ولا تُحفظ في أي ملف).
  - الناتج: سطر ADMINS يحتوي بصمة كلمة السر (scrypt) وسر التحقق الثنائي، تضعه كمتغير بيئة على الاستضافة.
  - لا ترسل هذا السطر لأحد ولا ترفعه على GitHub.
*/

const crypto = require("node:crypto");
const readline = require("node:readline");
const { promisify } = require("node:util");
const totp = require("../server/totp");

const scrypt = promisify(crypto.scrypt);

// قراءة سطر بدون إظهاره على الشاشة (للطرفية)، أو من الإدخال المُمرَّر (للاختبار الآلي)
function createInput() {
    if (!process.stdin.isTTY) {
        const rl = readline.createInterface({ input: process.stdin });
        const lines = [];
        const waiting = [];
        let closed = false;
        rl.on("line", line => (waiting.length ? waiting.shift()(line) : lines.push(line)));
        rl.on("close", () => { closed = true; while (waiting.length) waiting.shift()(""); });
        return { hidden: () => new Promise(resolve => (lines.length ? resolve(lines.shift()) : closed ? resolve("") : waiting.push(resolve))) };
    }
    return {
        hidden(prompt) {
            return new Promise(resolve => {
                process.stdout.write(prompt);
                const stdin = process.stdin;
                let value = "";
                stdin.setRawMode(true);
                stdin.resume();
                stdin.setEncoding("utf8");
                const onData = chunk => {
                    for (const ch of chunk) {
                        if (ch === "\r" || ch === "\n" || ch === "\u0004") {
                            stdin.setRawMode(false);
                            stdin.pause();
                            stdin.removeListener("data", onData);
                            process.stdout.write("\n");
                            resolve(value);
                            return;
                        }
                        if (ch === "\u0003") process.exit(130);
                        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
                        else value += ch;
                    }
                };
                stdin.on("data", onData);
            });
        }
    };
}

const COMMON = new Set(["password1234", "123456789012", "qwertyuiop12", "admin1234567", "letmein12345"]);

async function main() {
    const username = (process.argv[2] || "").toLowerCase();
    if (!/^[a-z0-9_.-]{3,32}$/.test(username)) {
        console.log("Usage: npm run make-admin -- <username>    (3-32 chars: a-z 0-9 _ . -)");
        process.exit(1);
    }

    const input = createInput();
    const password = await input.hidden("Password (at least 12 characters): ");
    const again = await input.hidden("Repeat the password: ");

    if (password.length < 12) fail("Password is too short (minimum 12 characters).");
    if (password !== again) fail("The two passwords do not match.");
    if (password.toLowerCase().includes(username) || COMMON.has(password.toLowerCase()) || /^(.)\1+$/.test(password)) {
        fail("Password is too easy to guess. Use a long, unique passphrase.");
    }

    const salt = crypto.randomBytes(16).toString("hex");
    const hash = (await scrypt(password, salt, 32)).toString("hex");
    const secret = totp.generateSecret();

    console.log("\n=== Done. Keep everything below secret ===\n");
    console.log("1) Set this environment variable on your host (Render > Environment):\n");
    console.log(`   ADMINS=${username}:${salt}:${hash}:${secret}\n`);
    console.log("2) Add the 2-step verification to your authenticator app (Google/Microsoft Authenticator):");
    console.log("   choose 'Enter a setup key' and type:\n");
    console.log(`   Account: ${username}`);
    console.log(`   Key:     ${secret}`);
    console.log("   Type:    time based\n");
    console.log(`   (or open this link on your phone: ${totp.otpauthUri(secret, username)})\n`);
    console.log("To allow several admins, join the entries with a comma. To disable 2-step verification,");
    console.log("remove the last ':' part (not recommended).");
}

function fail(message) {
    console.log("\nError: " + message);
    process.exit(1);
}

main().catch(error => fail(error.message));
