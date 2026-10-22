use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum I18nError {
    #[error("unsupported locale: {0}")]
    UnsupportedLocale(String),

    #[error("failed to load translation file: {0}")]
    LoadError(String),

    #[error("translation key not found: {0}")]
    KeyNotFound(String),

    #[error("failed to parse translation file: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, I18nError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Locale {
    En,
    Es,
    Fr,
    De,
    Zh,
    Ja,
    Ko,
    Pt,
    Ru,
    Ar,
}

impl Locale {
    pub fn all() -> &'static [Locale] {
        &[
            Locale::En,
            Locale::Es,
            Locale::Fr,
            Locale::De,
            Locale::Zh,
            Locale::Ja,
            Locale::Ko,
            Locale::Pt,
            Locale::Ru,
            Locale::Ar,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Locale::En => "en",
            Locale::Es => "es",
            Locale::Fr => "fr",
            Locale::De => "de",
            Locale::Zh => "zh",
            Locale::Ja => "ja",
            Locale::Ko => "ko",
            Locale::Pt => "pt",
            Locale::Ru => "ru",
            Locale::Ar => "ar",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            Locale::En => "English",
            Locale::Es => "Espanol",
            Locale::Fr => "Francais",
            Locale::De => "Deutsch",
            Locale::Zh => "Zhongwen",
            Locale::Ja => "Nihongo",
            Locale::Ko => "Hangugeo",
            Locale::Pt => "Portugues",
            Locale::Ru => "Russkiy",
            Locale::Ar => "Al-Arabiyyah",
        }
    }
}

impl fmt::Display for Locale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for Locale {
    type Err = I18nError;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "en" => Ok(Locale::En),
            "es" => Ok(Locale::Es),
            "fr" => Ok(Locale::Fr),
            "de" => Ok(Locale::De),
            "zh" => Ok(Locale::Zh),
            "ja" => Ok(Locale::Ja),
            "ko" => Ok(Locale::Ko),
            "pt" => Ok(Locale::Pt),
            "ru" => Ok(Locale::Ru),
            "ar" => Ok(Locale::Ar),
            _ => Err(I18nError::UnsupportedLocale(s.to_string())),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TranslationBundle {
    pub locale: Locale,
    translations: HashMap<String, String>,
}

impl TranslationBundle {
    pub fn new(locale: Locale) -> Self {
        Self {
            locale,
            translations: HashMap::new(),
        }
    }

    pub fn from_json(locale: Locale, json: &str) -> Result<Self> {
        let translations: HashMap<String, String> = serde_json::from_str(json)?;
        Ok(Self {
            locale,
            translations,
        })
    }

    pub fn from_file(locale: Locale, path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            I18nError::LoadError(format!("{}: {}", path.display(), e))
        })?;
        Self::from_json(locale, &content)
    }

    pub fn insert(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.translations.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.translations.get(key).map(|s| s.as_str())
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.translations.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.translations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.translations.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.translations.keys().map(|k| k.as_str())
    }
}

fn build_default_english() -> TranslationBundle {
    let json = include_str!("../translations/en.json");
    TranslationBundle::from_json(Locale::En, json)
        .expect("built-in English translations are invalid")
}

#[derive(Debug, Clone)]
pub struct TranslationManager {
    bundles: HashMap<Locale, TranslationBundle>,
    current_locale: Locale,
    fallback_locale: Locale,
}

impl TranslationManager {
    pub fn new() -> Self {
        let default_bundle = build_default_english();
        let mut bundles = HashMap::new();
        bundles.insert(Locale::En, default_bundle);

        Self {
            bundles,
            current_locale: Locale::En,
            fallback_locale: Locale::En,
        }
    }

    pub fn load_language(&mut self, path: &Path) -> Result<Locale> {
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        let locale: Locale = stem.parse()?;
        let bundle = TranslationBundle::from_file(locale, path)?;
        self.bundles.insert(locale, bundle);
        Ok(locale)
    }

    pub fn load_language_from_json(&mut self, locale: Locale, json: &str) -> Result<()> {
        let bundle = TranslationBundle::from_json(locale, json)?;
        self.bundles.insert(locale, bundle);
        Ok(())
    }

    pub fn set_language(&mut self, locale: Locale) {
        self.current_locale = locale;
    }

    pub fn set_fallback_locale(&mut self, locale: Locale) {
        self.fallback_locale = locale;
    }

    pub fn current_locale(&self) -> Locale {
        self.current_locale
    }

    pub fn available_locales(&self) -> Vec<Locale> {
        self.bundles.keys().copied().collect()
    }

    pub fn has_language(&self, locale: Locale) -> bool {
        self.bundles.contains_key(&locale)
    }

    pub fn translate(&self, key: &str) -> String {
        self.translate_with_params(key, &[])
    }

    pub fn translate_with_params(&self, key: &str, params: &[(&str, &str)]) -> String {
        let template = self
            .bundles
            .get(&self.current_locale)
            .and_then(|b| b.get(key))
            .or_else(|| {
                self.bundles
                    .get(&self.fallback_locale)
                    .and_then(|b| b.get(key))
            });

        match template {
            Some(t) => apply_params(t, params),
            None => key.to_string(),
        }
    }

    pub fn translate_param(&self, key: &str, params: &HashMap<&str, &str>) -> String {
        let template = self
            .bundles
            .get(&self.current_locale)
            .and_then(|b| b.get(key))
            .or_else(|| {
                self.bundles
                    .get(&self.fallback_locale)
                    .and_then(|b| b.get(key))
            });

        match template {
            Some(t) => {
                let mut result = t.to_string();
                for (k, v) in params {
                    result = result.replace(&format!("{{{}}}", k), v);
                }
                result
            }
            None => key.to_string(),
        }
    }

    pub fn bundle(&self, locale: Locale) -> Option<&TranslationBundle> {
        self.bundles.get(&locale)
    }

    pub fn register_bundle(&mut self, bundle: TranslationBundle) {
        self.bundles.insert(bundle.locale, bundle);
    }
}

impl Default for TranslationManager {
    fn default() -> Self {
        Self::new()
    }
}

fn apply_params(template: &str, params: &[(&str, &str)]) -> String {
    let mut result = template.to_string();
    for (key, value) in params {
        result = result.replace(&format!("{{{}}}", key), value);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manager() -> TranslationManager {
        let mut mgr = TranslationManager::new();
        let es_json = r#"{
            "app.title": "Recuperacion de Datos",
            "recovery.start": "Iniciar recuperacion",
            "recovery.progress": "Recuperados {count} archivos de {total}",
            "error.file_not_found": "Archivo no encontrado: {path}",
            "status.complete": "Completado"
        }"#;
        mgr.load_language_from_json(Locale::Es, es_json).unwrap();
        mgr
    }

    #[test]
    fn test_default_english_loaded() {
        let mgr = TranslationManager::new();
        assert!(mgr.has_language(Locale::En));
        assert_eq!(mgr.current_locale(), Locale::En);
    }

    #[test]
    fn test_translate_english() {
        let mgr = TranslationManager::new();
        let result = mgr.translate("app.title");
        assert_ne!(result, "app.title", "should find app.title in default English bundle");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_set_and_translate_spanish() {
        let mut mgr = sample_manager();
        mgr.set_language(Locale::Es);
        assert_eq!(mgr.current_locale(), Locale::Es);

        let result = mgr.translate("status.complete");
        assert_eq!(result, "Completado");
    }

    #[test]
    fn test_parameterized_translation() {
        let mut mgr = sample_manager();
        mgr.set_language(Locale::Es);

        let result = mgr.translate_with_params(
            "recovery.progress",
            &[("count", "42"), ("total", "100")],
        );
        assert_eq!(result, "Recuperados 42 archivos de 100");
    }

    #[test]
    fn test_translate_param_with_hashmap() {
        let mut mgr = sample_manager();
        mgr.set_language(Locale::Es);

        let mut params = HashMap::new();
        params.insert("path", "/data/lost.txt");
        let result = mgr.translate_param("error.file_not_found", &params);
        assert_eq!(result, "Archivo no encontrado: /data/lost.txt");
    }

    #[test]
    fn test_fallback_to_english() {
        let mut mgr = sample_manager();
        mgr.set_language(Locale::Es);

        let result = mgr.translate("app.version");
        let en_result = TranslationManager::new().translate("app.version");
        assert_eq!(result, en_result, "should fall back to English for missing keys");
    }

    #[test]
    fn test_missing_key_returns_key() {
        let mgr = TranslationManager::new();
        let result = mgr.translate("nonexistent.key");
        assert_eq!(result, "nonexistent.key");
    }

    #[test]
    fn test_load_language_from_json() {
        let mut mgr = TranslationManager::new();
        let fr_json = r#"{"app.title": "Recuperation de Donnees"}"#;
        mgr.load_language_from_json(Locale::Fr, fr_json).unwrap();
        assert!(mgr.has_language(Locale::Fr));

        mgr.set_language(Locale::Fr);
        assert_eq!(mgr.translate("app.title"), "Recuperation de Donnees");
    }

    #[test]
    fn test_locale_from_str() {
        assert_eq!("en".parse::<Locale>().unwrap(), Locale::En);
        assert_eq!("es".parse::<Locale>().unwrap(), Locale::Es);
        assert_eq!("ES".parse::<Locale>().unwrap(), Locale::Es);
        assert!("xx".parse::<Locale>().is_err());
    }

    #[test]
    fn test_locale_display() {
        assert_eq!(Locale::En.to_string(), "en");
        assert_eq!(Locale::Zh.to_string(), "zh");
        assert_eq!(Locale::En.display_name(), "English");
        assert_eq!(Locale::Ja.display_name(), "Nihongo");
    }

    #[test]
    fn test_available_locales() {
        let mgr = sample_manager();
        let locales = mgr.available_locales();
        assert!(locales.contains(&Locale::En));
        assert!(locales.contains(&Locale::Es));
    }

    #[test]
    fn test_translation_bundle_operations() {
        let mut bundle = TranslationBundle::new(Locale::De);
        assert!(bundle.is_empty());

        bundle.insert("hello", "Hallo");
        assert_eq!(bundle.len(), 1);
        assert!(bundle.contains_key("hello"));
        assert_eq!(bundle.get("hello"), Some("Hallo"));
        assert_eq!(bundle.get("missing"), None);
    }

    #[test]
    fn test_translation_bundle_from_json() {
        let json = r#"{"key1": "value1", "key2": "value2"}"#;
        let bundle = TranslationBundle::from_json(Locale::En, json).unwrap();
        assert_eq!(bundle.len(), 2);
        assert_eq!(bundle.get("key1"), Some("value1"));
        assert_eq!(bundle.get("key2"), Some("value2"));
    }

    #[test]
    fn test_apply_params_no_params() {
        let result = apply_params("Hello world", &[]);
        assert_eq!(result, "Hello world");
    }

    #[test]
    fn test_apply_params_multiple() {
        let result = apply_params(
            "{name} recovered {count} files from {source}",
            &[("name", "Alice"), ("count", "5"), ("source", "disk")],
        );
        assert_eq!(result, "Alice recovered 5 files from disk");
    }

    #[test]
    fn test_register_bundle() {
        let mut mgr = TranslationManager::new();
        let mut bundle = TranslationBundle::new(Locale::Ja);
        bundle.insert("app.title", "Data Fukkyu");
        mgr.register_bundle(bundle);
        assert!(mgr.has_language(Locale::Ja));

        mgr.set_language(Locale::Ja);
        assert_eq!(mgr.translate("app.title"), "Data Fukkyu");
    }

    #[test]
    fn test_load_invalid_json() {
        let mut mgr = TranslationManager::new();
        let result = mgr.load_language_from_json(Locale::De, "not valid json{{{");
        assert!(result.is_err());
    }

    #[test]
    fn test_fallback_locale_custom() {
        let mut mgr = TranslationManager::new();
        let fr_json = r#"{"fallback.only": "Valeur de secours"}"#;
        mgr.load_language_from_json(Locale::Fr, fr_json).unwrap();

        mgr.set_fallback_locale(Locale::Fr);
        mgr.set_language(Locale::De);

        let result = mgr.translate("fallback.only");
        assert_eq!(result, "Valeur de secours");
    }

    #[test]
    fn test_all_locales_count() {
        assert_eq!(Locale::all().len(), 10);
    }
}
