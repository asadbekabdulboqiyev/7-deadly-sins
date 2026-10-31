# Arxitektura qarorlari (ADR)

## ADR-001 — Hydra brute-force, DDoS stress-test va qo'lda exploit v1 dan chiqarildi

**Sana:** 2026-10-31
**Holat:** qabul qilindi

### Kontekst
Dastlabki rejada 7 ta modul bor edi: Lust (Hydra brute-force), Gluttony
(DDoS/stress test), Wrath (SQLi/XSS payload yuborish).

### Qaror
Uchala modul ham v1 dan chiqarildi. Ularning funksiyasi nuclei
template'lari orqali qoplanadi (auth, rate-limit, exploit tekshiruvlari),
lekin **bizning kodimiz hech qanday payload yozmaydi**.

### Sabab
1. **Huquqiy** — ruxsatsiz brute-force/exploit = jinoyat. Nishon egaligi
   isbotlansa ham, noto'g'ri konfiguratsiya bitta mijozni jinoiy javobgarlikka
   olib boradi.
2. **Operatsion** — DDoS-as-a-service hosting provayderlari tomonidan
   48 soat ichida bloklanadi.
3. **Texnik** — Hydra chiqishi mashina o'qiy olmaydigan matn; parsing
   ishonchsiz.

### Natija
Huquqiy risk minimallashtirildi. Mahsulot "xakerlik vositasi" emas,
"audit platformasi" sifatida pozitsiyalanadi.

---

## ADR-002 — PostgreSQL, MongoDB emas

### Qaror
PostgreSQL.

### Sabab
- Finding'lar relatsion: `scan → target → finding → evidence → remediation`
- Dedup/korrelyatsiya uchun JOIN kerak
- Xom tool chiqishi uchun `jsonb` + GIN index yetarli (Mongo'ning asosiy
  afzalligi yo'qoladi)
- Multi-tenancy uchun Row-Level Security
- `pg_trgm` — fuzzy CVE matching; `tsvector` — qidiruv

---

## ADR-003 — nuclei, `nmap --script vulners` emas

### Sabab
- `vulners` pullik API key talab qiladi
- Service version → CVE mapping false positive darajasi juda yuqori
- nuclei `-jsonl` barqaror format beradi va 10 000+ tayyor template bor

---

## ADR-004 — `correlate()` da `sub_id` majburiy

### Kontekst
Birinchi implementatsiyada korrelyatsiya kaliti `host + title` edi.
`http-missing-security-headers` template'i 10 ta alohida muammo qaytardi
(har biri boshqa header), lekin ular **bitta** finding'ga birlashib ketdi.

### Qaror
`FindingContract.sub_id` qo'shildi. CVE bo'lmasa kalit:
`host + title + sub_id`. nuclei adapteri `sub_id = matcher-name` beradi.

### Natija
10 ta header = 10 ta finding. CVE bo'lsa esa ikki tool natijasi baribir
birlashadi.

---

## ADR-005 — Egress IP alohida boshqariladi

### Qaror
Skan container ichida, alohida network namespace va alohida egress IP
pool bilan ishlaydi. Worker hech qachon to'g'ridan-to'g'ri skanlamaydi.

### Sabab
Bitta IP'dan ko'p skan → blocklist + hosting akkaunti yopiladi. PTR yozuvi
`scanner.<domen>` bo'lishi shart.
