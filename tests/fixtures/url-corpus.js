"use strict";
// مدوّنة اختبار: روابط حقيقية (يجب أن تكون آمنة) وروابط احتيال (يجب ألا تكون آمنة)
const LEGIT = [
 'https://google.com','https://www.google.com/search?q=test','https://mail.google.com/mail/u/0/','https://accounts.google.com/signin',
 'https://facebook.com/login','https://m.facebook.com','https://www.instagram.com/p/abc/','https://web.whatsapp.com','https://wa.me/9647700000000',
 'https://t.me/somechannel','https://telegram.org','https://www.youtube.com/watch?v=dQw4w9WgXcQ','https://youtu.be/dQw4w9WgXcQ',
 'https://twitter.com/user','https://x.com/user','https://www.tiktok.com/@user','https://www.snapchat.com',
 'https://login.microsoftonline.com','https://outlook.live.com/mail','https://www.office.com','https://onedrive.live.com',
 'https://www.apple.com/iphone','https://appleid.apple.com','https://www.icloud.com','https://www.amazon.com/dp/B000',
 'https://www.netflix.com/browse','https://www.paypal.com/signin','https://www.binance.com/en','https://www.dhl.com/track',
 'https://www.linkedin.com/in/x','https://github.com/user/repo','https://www.yahoo.com','https://www.dropbox.com/s/abc',
 'https://zaincash.iq','https://rafidain-bank.gov.iq','https://rasheedbank.gov.iq','https://fib.iq','https://www.asiacell.com',
 'https://www.korektel.com','https://qi.iq','https://tu.edu.iq','https://mohesr.gov.iq','https://uobaghdad.edu.iq',
 'https://www.wikipedia.org','https://ar.wikipedia.org/wiki/العراق','https://www.bbc.com/arabic','https://www.aljazeera.net',
 'https://www.alsumaria.tv','https://www.shafaq.com','https://www.ina.iq','https://stackoverflow.com/questions/1',
 'https://www.reddit.com/r/iraq','https://www.coursera.org','https://www.udemy.com','https://www.w3schools.com',
 'https://developer.mozilla.org','https://www.npmjs.com','https://www.python.org','https://www.zoom.us','https://meet.google.com/abc-defg-hij',
 'https://docs.google.com/document/d/1','https://drive.google.com/file/d/1/view','https://www.canva.com','https://www.spotify.com',
 'https://store.steampowered.com','https://www.roblox.com','https://www.adobe.com','https://www.booking.com','https://www.airbnb.com',
 'https://www.aliexpress.com','https://www.ebay.com','https://www.temu.com','https://www.shein.com','https://www.noon.com',
 'https://www.talabat.com','https://www.careem.com','https://www.uber.com','https://www.opensooq.com','https://www.cloudflare.com',
 'https://chat.openai.com','https://claude.ai','https://www.speedtest.net','https://www.bing.com','https://duckduckgo.com',
 'https://www.imdb.com','https://www.nytimes.com','https://www.cnn.com','https://www.espn.com','https://www.fifa.com',
 'https://www.microsoft.com/ar-iq','https://support.apple.com','https://help.instagram.com','https://business.facebook.com',
 'https://play.google.com/store/apps/details?id=com.whatsapp','https://apps.apple.com/app/id310633997','https://news.google.com',
 'https://maps.google.com','https://translate.google.com','https://www.gov.uk','https://www.irs.gov','https://www.who.int',
 'https://www.un.org','https://www.unicef.org','https://www.mit.edu','https://www.harvard.edu','https://www.ox.ac.uk',
 'http://example.com','https://example.org/path?x=1','https://my-small-bakery.com','https://ali-hassan-portfolio.netlify.app',
 'https://shop.mybrand.co','https://blog.someone.dev','https://www.uokerbala.edu.iq','https://www.uomosul.edu.iq','https://www.moi.gov.iq',
 'https://www.cbi.iq','https://www.tbi.com.iq','https://www.bankofbaghdad.com.iq','https://www.earthlink.iq','https://www.zain.iq',
];
const BRANDS = ['google','facebook','paypal','apple','microsoft','amazon','netflix','instagram','whatsapp','binance','zaincash','rafidain','asiacell','qicard','outlook','telegram','tiktok','linkedin','dropbox','coinbase'];
const PHISH = [];
const tlds = ['com','net','xyz','top','info','online','site','live','click','support'];
for (const b of BRANDS) {
  const sub = b.replace(/o/,'0').replace(/l/,'1');
  if (sub !== b) PHISH.push(`https://${sub}.com/login`);
  PHISH.push(`https://${b}-secure-login.${tlds[b.length%tlds.length]}/verify`);
  PHISH.push(`https://${b}.verify-account.${tlds[(b.length+3)%tlds.length]}/`);
  PHISH.push(`https://login-${b}.${tlds[(b.length+5)%tlds.length]}`);
  PHISH.push(`https://${b.slice(0,-1)+b.slice(-1)+b.slice(-1)}.com/signin`);           // حرف مكرر
  PHISH.push(`https://${b[1]+b[0]+b.slice(2)}.com/account`);                             // تبديل حرفين
  PHISH.push(`https://${b}-support-center.net/update?id=1`);
  PHISH.push(`https://secure.${b}.com.account-update.${tlds[b.length%tlds.length]}/`);
  PHISH.push(`http://${b}.com-login.info/`);
}
PHISH.push('http://192.168.1.10/paypal/login.php','http://45.77.12.3/bank/verify','http://0x2d4d0c03/login','http://3044480003/secure',
  'https://xn--pypal-4ve.com','https://xn--80ak6aa92e.com','https://bit.ly/3xYz12','https://tinyurl.com/ab12cd',
  'https://google.com@evil.example/login','https://evil.example/https://paypal.com/login','https://faceboook.com','https://instagramm.com',
  'https://whatsap.com','https://rafidain-update.com/login','https://zain-cash-gift.top','https://asiacell-gift.xyz/claim',
  'https://qicard-verify.online/otp','https://fib-iq-secure.site','https://apple-id-locked.online','https://appleid-apple.com.verify.live',
  'https://netflix-payment-update.com','https://amazon-prize-winner.click','https://binance-airdrop-claim.xyz','https://kdjf8sd7f6sd8f7.xyz/login',
  'https://login.microsoftonline.com.secure-auth.top','https://docs-google.com/forms','https://g00gle.com','https://micr0soft-support.com',
  'https://paypa1.com/signin','https://arnazon.com','https://rnicrosoft.com');
module.exports = { LEGIT, PHISH };
