# patchdiff — açıklık dersleri

Güvenlik yamalarını diff'leyerek öğrenmek için ders sayfaları: yamasız ve yamalı kodun farkı, kök nedeni
önce kendin tahmin et, sonra cevap anahtarı ve AI açıklamasıyla karşılaştır.

**Site:** https://ka1nsha.github.io/patchdiff/

Dersler yalnızca kök nedeni ve yamanın etkisini anlatır; exploit, PoC ya da tetikleyici girdi içermez.

## Düzen

| Yol | İçerik |
|---|---|
| `content/lessons/<CVE>.md` | Yayımlanan dersler: YAML frontmatter (künye, ipuçları, kaynaklar, AI satır yorumları) + Markdown bölümler |
| `engine/` | Sayfaları üreten render motoru (patchdiff-tutor'dan kopyalanır; elle değiştirme) |
| `.github/workflows/pages.yml` | Her push'ta `content/`'i `engine/` ile statik siteye çevirip GitHub Pages'e koyar |

Yerelde üretmek için:

```bash
pip install -r engine/requirements.txt
cd engine && python -m pdt_web.publish build ../content ../_site
```

Bu repo patchdiff-tutor'un YAYINLA düğmesiyle güncellenir.
