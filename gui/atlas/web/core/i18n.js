import en from '../locales/en.json' with { type: 'json' };
import az from '../locales/az.json' with { type: 'json' };
import az_latin from '../locales/az@latin.json' with { type: 'json' };
import be from '../locales/be.json' with { type: 'json' };
import bg from '../locales/bg.json' with { type: 'json' };
import bn from '../locales/bn.json' with { type: 'json' };
import br from '../locales/br.json' with { type: 'json' };
import bs from '../locales/bs.json' with { type: 'json' };
import ca from '../locales/ca.json' with { type: 'json' };
import cmn from '../locales/cmn.json' with { type: 'json' };
import cs from '../locales/cs.json' with { type: 'json' };
import cy from '../locales/cy.json' with { type: 'json' };
import da from '../locales/da.json' with { type: 'json' };
import de_CH from '../locales/de_CH.json' with { type: 'json' };
import el from '../locales/el.json' with { type: 'json' };
import eo from '../locales/eo.json' with { type: 'json' };
import es from '../locales/es.json' with { type: 'json' };
import es_CL from '../locales/es_CL.json' with { type: 'json' };
import es_CO from '../locales/es_CO.json' with { type: 'json' };
import es_DO from '../locales/es_DO.json' with { type: 'json' };
import es_SV from '../locales/es_SV.json' with { type: 'json' };
import es_VE from '../locales/es_VE.json' with { type: 'json' };
import et from '../locales/et.json' with { type: 'json' };
import eu from '../locales/eu.json' with { type: 'json' };
import fi from '../locales/fi.json' with { type: 'json' };
import fil from '../locales/fil.json' with { type: 'json' };
import fr from '../locales/fr.json' with { type: 'json' };
import ga from '../locales/ga.json' with { type: 'json' };
import ga_IE from '../locales/ga_IE.json' with { type: 'json' };
import gl from '../locales/gl.json' with { type: 'json' };
import gu from '../locales/gu.json' with { type: 'json' };
import hak from '../locales/hak.json' with { type: 'json' };
import he from '../locales/he.json' with { type: 'json' };
import hr from '../locales/hr.json' with { type: 'json' };
import hu from '../locales/hu.json' with { type: 'json' };
import id from '../locales/id.json' with { type: 'json' };
import is from '../locales/is.json' with { type: 'json' };
import it from '../locales/it.json' with { type: 'json' };
import ja from '../locales/ja.json' with { type: 'json' };
import ka from '../locales/ka.json' with { type: 'json' };
import kk from '../locales/kk.json' with { type: 'json' };
import kk_latin from '../locales/kk@latin.json' with { type: 'json' };
import km from '../locales/km.json' with { type: 'json' };
import ko from '../locales/ko.json' with { type: 'json' };
import ky from '../locales/ky.json' with { type: 'json' };
import lt from '../locales/lt.json' with { type: 'json' };
import lv from '../locales/lv.json' with { type: 'json' };
import mg from '../locales/mg.json' with { type: 'json' };
import mk from '../locales/mk.json' with { type: 'json' };
import mn from '../locales/mn.json' with { type: 'json' };
import ms from '../locales/ms.json' with { type: 'json' };
import nb from '../locales/nb.json' with { type: 'json' };
import pl from '../locales/pl.json' with { type: 'json' };
import ps from '../locales/ps.json' with { type: 'json' };
import pt from '../locales/pt.json' with { type: 'json' };
import pt_BR from '../locales/pt_BR.json' with { type: 'json' };
import ro from '../locales/ro.json' with { type: 'json' };
import ru from '../locales/ru.json' with { type: 'json' };
import si from '../locales/si.json' with { type: 'json' };
import sk from '../locales/sk.json' with { type: 'json' };
import sl from '../locales/sl.json' with { type: 'json' };
import sm from '../locales/sm.json' with { type: 'json' };
import sn from '../locales/sn.json' with { type: 'json' };
import sq from '../locales/sq.json' with { type: 'json' };
import sr from '../locales/sr.json' with { type: 'json' };
import sr_ijekavianlatin from '../locales/sr@ijekavianlatin.json' with { type: 'json' };
import sr_latin from '../locales/sr@latin.json' with { type: 'json' };
import sv from '../locales/sv.json' with { type: 'json' };
import szl from '../locales/szl.json' with { type: 'json' };
import ta from '../locales/ta.json' with { type: 'json' };
import te from '../locales/te.json' with { type: 'json' };
import th from '../locales/th.json' with { type: 'json' };
import tk from '../locales/tk.json' with { type: 'json' };
import tl from '../locales/tl.json' with { type: 'json' };
import tr from '../locales/tr.json' with { type: 'json' };
import uk from '../locales/uk.json' with { type: 'json' };
import ur from '../locales/ur.json' with { type: 'json' };
import uz from '../locales/uz.json' with { type: 'json' };
import uz_Cyrl from '../locales/uz@Cyrl.json' with { type: 'json' };
import uz_Latn from '../locales/uz@Latn.json' with { type: 'json' };
import yue from '../locales/yue.json' with { type: 'json' };
import zh from '../locales/zh.json' with { type: 'json' };
import zh_CN from '../locales/zh_CN.json' with { type: 'json' };
import zh_HK from '../locales/zh_HK.json' with { type: 'json' };
import zh_Hans from '../locales/zh_Hans.json' with { type: 'json' };
import zh_Hant from '../locales/zh_Hant.json' with { type: 'json' };
import zh_TW from '../locales/zh_TW.json' with { type: 'json' };

const FAMILIES = new Set(['system-ui', 'ui-sans-serif', 'ui-serif', 'ui-monospace', 'sans-serif', 'serif', 'monospace']);
const CATALOGS = {
  en: en,
  az: az,
  "az@latin": az_latin,
  be: be,
  bg: bg,
  bn: bn,
  br: br,
  bs: bs,
  ca: ca,
  cmn: cmn,
  cs: cs,
  cy: cy,
  da: da,
  de_CH: de_CH,
  el: el,
  eo: eo,
  es: es,
  es_CL: es_CL,
  es_CO: es_CO,
  es_DO: es_DO,
  es_SV: es_SV,
  es_VE: es_VE,
  et: et,
  eu: eu,
  fi: fi,
  fil: fil,
  fr: fr,
  ga: ga,
  ga_IE: ga_IE,
  gl: gl,
  gu: gu,
  hak: hak,
  he: he,
  hr: hr,
  hu: hu,
  id: id,
  is: is,
  it: it,
  ja: ja,
  ka: ka,
  kk: kk,
  "kk@latin": kk_latin,
  km: km,
  ko: ko,
  ky: ky,
  lt: lt,
  lv: lv,
  mg: mg,
  mk: mk,
  mn: mn,
  ms: ms,
  nb: nb,
  pl: pl,
  ps: ps,
  pt: pt,
  pt_BR: pt_BR,
  ro: ro,
  ru: ru,
  si: si,
  sk: sk,
  sl: sl,
  sm: sm,
  sn: sn,
  sq: sq,
  sr: sr,
  "sr@ijekavianlatin": sr_ijekavianlatin,
  "sr@latin": sr_latin,
  sv: sv,
  szl: szl,
  ta: ta,
  te: te,
  th: th,
  tk: tk,
  tl: tl,
  tr: tr,
  uk: uk,
  ur: ur,
  uz: uz,
  "uz@Cyrl": uz_Cyrl,
  "uz@Latn": uz_Latn,
  yue: yue,
  zh: zh,
  zh_CN: zh_CN,
  zh_HK: zh_HK,
  zh_Hans: zh_Hans,
  zh_Hant: zh_Hant,
  zh_TW: zh_TW,
};
export const CATALOG_LANGS = ["en", "az", "az@latin", "be", "bg", "bn", "br", "bs", "ca", "cmn", "cs", "cy", "da", "de_CH", "el", "eo", "es", "es_CL", "es_CO", "es_DO", "es_SV", "es_VE", "et", "eu", "fi", "fil", "fr", "ga", "ga_IE", "gl", "gu", "hak", "he", "hr", "hu", "id", "is", "it", "ja", "ka", "kk", "kk@latin", "km", "ko", "ky", "lt", "lv", "mg", "mk", "mn", "ms", "nb", "pl", "ps", "pt", "pt_BR", "ro", "ru", "si", "sk", "sl", "sm", "sn", "sq", "sr", "sr@ijekavianlatin", "sr@latin", "sv", "szl", "ta", "te", "th", "tk", "tl", "tr", "uk", "ur", "uz", "uz@Cyrl", "uz@Latn", "yue", "zh", "zh_CN", "zh_HK", "zh_Hans", "zh_Hant", "zh_TW"];

export function t(key, lang) {
  const catalog = Object.hasOwn(CATALOGS, lang) ? CATALOGS[lang] : CATALOGS.en;
  if (catalog && Object.hasOwn(catalog, key) && typeof catalog[key] === 'string' && catalog[key] !== '') return catalog[key];
  if (Object.hasOwn(CATALOGS.en, key) && typeof CATALOGS.en[key] === 'string' && CATALOGS.en[key] !== '') return CATALOGS.en[key];
  return key;
}

export function fontFamily(value) {
  if (typeof value !== 'string') return '';
  const folded = value.toLowerCase();
  if (folded.includes('url') || folded.includes('http') || value.includes('@') || value.includes('(') || value.includes(')')) return '';
  return FAMILIES.has(value) ? value : '';
}
