// «مسك بوت» — قلب البوت (مجاني، بدون أي خدمة خارجية). مشترك بين السيرفر والديمو.
// صيغة القواعد (سطر لكل قاعدة):   كلمة1, كلمة2 = رد1 || رد2
//   * في أول السطر = القاعدة تشتغل حتى بدون مناداة البوت (مثل السلام)
//   {name} = اسم العضو
(function (root, factory) { if (typeof module === 'object' && module.exports) module.exports = factory(); else root.MiskBot = factory(); })(typeof self !== 'undefined' ? self : this, function () {
  const NAME = 'مسك بوت';
  const DEFAULT_RULES = [
    '*السلام عليكم, سلام عليكم, السلام = وعليكم السلام ورحمة الله وبركاته يا {name} 🌹 || أهلاً {name}، نورت الشات',
    '*مرحبا, هاي, هلا, اهلا, أهلا = أهلاً بيك يا {name} 🌸 || نورت يا {name}، منور الشات',
    'صباح الخير = صباح النور يا {name} ☀️ || صباح الورد والفل',
    'مساء الخير = مساء النور يا {name} 🌙 || مساء الفل',
    'ازيك, عامل ايه, عامله ايه, اخبارك = الحمد لله تمام يا {name}، وانت عامل ايه؟ || تمام الحمد لله، منور',
    'انت مين, مين انت, انت ايه = أنا مسك بوت، مساعد الشات 🤖 بأرحب بالناس وبساعد المشرفين',
    'مساعدة, مساعده, help, ساعدني = اكتب القوانين لو عاوز تعرف قواعد الشات، وتقدر تبلغ المشرفين من قايمة المتواجدين. وأنا موجود لو احتجت حاجة',
    'القوانين, قوانين, القواعد = احترم الجميع، ممنوع السب والإساءة والروابط المشبوهة. والمخالف بيتكتم مؤقتًا',
    'شكرا, شكراً, متشكر, تسلم = العفو يا {name} 🌹 || ولا يهمك، في الخدمة',
    'باي, سلام, مع السلامه, تصبح على خير = مع السلامة يا {name}، نورتنا 👋 || في أمان الله يا {name}',
    'نكتة, نكته, قولي نكتة = مرة واحد راح للدكتور قاله: كل يوم تمشي ساعة. قاله: وانا بحب اقعد ساعتين 😂 || واحد قال لصاحبه: انا بنام بدري. قاله: ليه؟ قاله: عشان اصحى بدري واكمل نوم 😴',
    'احبك, بحبك = وانا كمان بحب الشات ده وناسه ❤️',
  ].join('\n');
  const FALLBACK = ['مش فاهم قصدك يا {name} 🤔 جرب تكتب "مساعدة"', 'قولي تاني يا {name}؟ لسه بتعلم 🙂', 'أنا بوت بسيط يا {name}، جرب "مساعدة" وأنا أقولك أقدر أعمل ايه'];
  const DEFAULT_BAD = '';

  const nd = s => String(s ?? '').replace(/[٠-٩]/g, c => c.charCodeAt(0) - 0x0660).replace(/[۰-۹]/g, c => c.charCodeAt(0) - 0x06f0);
  // توحيد النص العربي: تشكيل، تطويل، همزات، ياء/ألف مقصورة، تاء مربوطة، تكرار الحروف
  const norm = s => nd(s).toLowerCase().normalize('NFKC').replace(/[ً-ٰـ]/g, '').replace(/[أإآٱ]/g, 'ا').replace(/ى/g, 'ي').replace(/ة/g, 'ه').replace(/(.)\1{2,}/gu, '$1$1').replace(/[^\p{L}\p{N}@\s]/gu, ' ').replace(/\s+/g, ' ').trim();

  function parseRules(text) {
    const out = [];
    String(text ?? '').split('\n').forEach(line => {
      line = line.trim(); if (!line || line.startsWith('#')) return;
      const i = line.indexOf('='); if (i < 1) return;
      let left = line.slice(0, i).trim(), pub = false;
      if (left.startsWith('*')) { pub = true; left = left.slice(1).trim(); }
      const triggers = left.split(/[,،]/).map(norm).filter(Boolean), replies = line.slice(i + 1).split('||').map(x => x.trim()).filter(Boolean);
      if (triggers.length && replies.length) out.push({ triggers, replies, pub });
    });
    return out;
  }
  const hasPhrase = (hay, t) => (' ' + hay + ' ').includes(' ' + t + ' ');

  class Bot {
    constructor(o = {}) {
      this.name = o.name || NAME; this.rng = o.rng || Math.random;
      this.setRules(o.rules != null ? o.rules : DEFAULT_RULES); this.setBad(o.bad || DEFAULT_BAD);
      this.last = new Map(); // آخر رد لكل مفتاح (حد معدل)
      this.flood = new Map();
    }
    setRules(t) { this.rules = parseRules(t); }
    setBad(t) { this.bad = String(t ?? '').split(/[\n,،]+/).map(norm).filter(Boolean); }
    pick(a, name) { return a[Math.floor(this.rng() * a.length)].replace(/\{name\}/g, name || ''); }
    mentioned(text) { const n = norm(text), me = norm(this.name); return n.includes(me) || n.includes('@' + me) || n.includes('مسك بوت'); }
    strip(text) { const me = norm(this.name); return norm(text).replace(new RegExp('@?' + me.replace(/\s/g, '\\s*'), 'g'), ' ').replace(/\s+/g, ' ').trim(); }
    match(n, pubOnly) { return this.rules.find(r => (!pubOnly || r.pub) && r.triggers.some(t => hasPhrase(n, t))); }
    // رد في الغرفة: بالمناداة → أي قاعدة أو رد افتراضي، بدون مناداة → القواعد العامة فقط
    reply(text, name, now = Date.now(), key = '') {
      const ment = this.mentioned(text), n = ment ? this.strip(text) : norm(text);
      if (!n && !ment) return null;
      const r = this.match(n, !ment);
      if (!r && !ment) return null;
      const k = (r ? 'r' + this.rules.indexOf(r) : 'f') + '|' + (ment ? 'm' : 'p') + '|' + key;
      if (now - (this.last.get(k) || 0) < (ment ? 4000 : 25000)) return null;
      this.last.set(k, now); if (this.last.size > 500) this.last.clear();
      return r ? this.pick(r.replies, name) : this.pick(FALLBACK, name);
    }
    // رد في الخاص: دايمًا يرد
    pm(text, name) { const n = this.strip(text) || norm(text), r = this.match(n, false); return r ? this.pick(r.replies, name) : this.pick(FALLBACK, name); }
    welcome(name) { return this.pick(['أهلاً بيك يا {name} 🌸', 'نورت يا {name}، منور الشات', 'يا هلا بـ {name} 🌹'], name); }
    // مراقبة: ترجع {mins, why} لو لازم كتم مؤقت
    check(text, key, now = Date.now()) {
      const n = norm(text);
      if (this.bad.some(w => hasPhrase(n, w) || (w.length > 3 && n.includes(w)))) return { mins: 5, why: 'كلمة ممنوعة' };
      const a = (this.flood.get(key) || []).filter(x => now - x.t < 20000); a.push({ t: now, n }); this.flood.set(key, a); if (this.flood.size > 1000) this.flood.clear();
      if (n && a.filter(x => x.n === n).length >= 4) return { mins: 3, why: 'تكرار نفس الرسالة (سبام)' };
      return null;
    }
  }
  return { Bot, NAME, DEFAULT_RULES, DEFAULT_BAD, parseRules, norm };
});
