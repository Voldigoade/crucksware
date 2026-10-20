#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub enum Language {
    #[default]
    English,
    French,
    Spanish,
    SimplifiedChinese,
}

impl Language {
    pub const ALL: [Self; 4] = [
        Self::English,
        Self::French,
        Self::Spanish,
        Self::SimplifiedChinese,
    ];

    pub fn parse(code: &str) -> Option<Self> {
        match code {
            "en" => Some(Self::English),
            "fr" => Some(Self::French),
            "es" => Some(Self::Spanish),
            "zh-CN" => Some(Self::SimplifiedChinese),
            _ => None,
        }
    }

    pub const fn code(self) -> &'static str {
        match self {
            Self::English => "en",
            Self::French => "fr",
            Self::Spanish => "es",
            Self::SimplifiedChinese => "zh-CN",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::English => "English",
            Self::French => "Français",
            Self::Spanish => "Español",
            Self::SimplifiedChinese => "简体中文",
        }
    }
}
