use std::fmt::Display;

use rand::{thread_rng, Rng};
use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ChannelIDError {
    #[error("Channel ID must be 3 digits or fewer.")]
    OutOfRange,
    #[error("Channel ID is Disallowed.")]
    Disallowed,
}

/// A 3-digit channel ID
///
/// Channel IDs can not be one of the following:
/// * 333
/// * 444
/// * 555
/// * 666
/// * 777
/// * 888
/// * 999
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ChannelID(u16);

impl ChannelID {
    const DISALLOWED_CHANNEL_IDS: [u16; 7] = [333, 444, 555, 666, 777, 888, 999];

    pub fn new(id: u16) -> Result<Self, ChannelIDError> {
        if id > 999 {
            return Err(ChannelIDError::OutOfRange);
        }
        if Self::DISALLOWED_CHANNEL_IDS.contains(&id) {
            return Err(ChannelIDError::Disallowed);
        }
        Ok(Self(id))
    }

    pub fn random() -> Self {
        let id = loop {
            let id = thread_rng().gen_range(0..999);
            if !Self::DISALLOWED_CHANNEL_IDS.contains(&id) {
                break id;
            }
        };
        Self(id)
    }
}

impl Display for ChannelID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:03}", self.0)
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum SerialError {
    #[error("Serial must be 7 digits or fewer.")]
    OutOfRange,
    #[error("Sum of Serial digits must be divisible by 7.")]
    Invalid,
}

/// A 7-digit serial number
///
/// The sum of the digits of the serial number must be divisible by 7.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Serial(u32);

impl Serial {
    pub fn new(id: u32) -> Result<Self, SerialError> {
        if id > 9999999 {
            return Err(SerialError::OutOfRange);
        }
        let sum_of_digits = id
            .to_string()
            .chars()
            .map(|c| c.to_digit(10).unwrap())
            .sum::<u32>();
        if sum_of_digits % 7 != 0 {
            return Err(SerialError::Invalid);
        }
        Ok(Self(id))
    }

    pub fn random() -> Self {
        let id = loop {
            let id = thread_rng().gen_range(0..9999999);
            let sum_of_digits = id
                .to_string()
                .chars()
                .map(|c| c.to_digit(10).unwrap())
                .sum::<u32>();
            if sum_of_digits % 7 == 0 {
                break id;
            }
        };
        Self(id)
    }
}

impl Display for Serial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:07}", self.0)
    }
}

/// A 2-digit year
pub enum Year {
    Year95,
    Year96,
    Year97,
    Year98,
    Year99,
    Year00,
    Year01,
    Year02,
}

impl Year {
    pub fn random() -> Self {
        let year = thread_rng().gen_range(0..8);
        match year {
            0 => Self::Year95,
            1 => Self::Year96,
            2 => Self::Year97,
            3 => Self::Year98,
            4 => Self::Year99,
            5 => Self::Year00,
            6 => Self::Year01,
            7 => Self::Year02,
            _ => panic!(),
        }
    }
}

impl Display for Year {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let year = match self {
            Year::Year95 => "95",
            Year::Year96 => "96",
            Year::Year97 => "97",
            Year::Year98 => "98",
            Year::Year99 => "99",
            Year::Year00 => "00",
            Year::Year01 => "01",
            Year::Year02 => "02",
        };
        write!(f, "{year}")
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum DayError {
    #[error("Day must be between 0 and 365 (exclusive).")]
    OutOfRange,
}

/// A 3-digit day
///
/// The day must be between 0 and 365 (exclusive).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Day(u16);

impl Day {
    pub fn new(day: u16) -> Result<Self, DayError> {
        if day == 0 || day >= 365 {
            return Err(DayError::OutOfRange);
        }
        Ok(Self(day))
    }

    pub fn random() -> Self {
        Self(thread_rng().gen_range(1..365))
    }
}

impl Display for Day {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:03}", self.0)
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum OemIDError {
    #[error("OEM ID must be 5 digits or fewer.")]
    OutOfRange,
    #[error("Sum of OEM ID digits must be divisible by 7.")]
    Invalid,
}

/// A 5-digit OEM ID
///
/// The sum of the digits of the OEM ID must be divisible by 7.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OemID(u32);

impl OemID {
    pub fn new(id: u32) -> Result<Self, OemIDError> {
        if id > 99999 {
            return Err(OemIDError::OutOfRange);
        }
        let sum_of_digits = id
            .to_string()
            .chars()
            .map(|c| c.to_digit(10).unwrap())
            .sum::<u32>();
        if sum_of_digits % 7 != 0 {
            return Err(OemIDError::Invalid);
        }
        Ok(Self(id))
    }

    pub fn random() -> Self {
        let id = loop {
            let id = thread_rng().gen_range(0..99999);
            let sum_of_digits = id
                .to_string()
                .chars()
                .map(|c| c.to_digit(10).unwrap())
                .sum::<u32>();
            if sum_of_digits % 7 == 0 {
                break id;
            }
        };
        Self(id)
    }
}

impl Display for OemID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "00{:05}", self.0)
    }
}

/// Generates a product key for the retail version of 95.
///
/// Any of the parameters can be `None` to generate a random value.
pub fn generate_retail(channel_id: Option<ChannelID>, serial: Option<Serial>) -> String {
    let channel_id = channel_id.unwrap_or_else(ChannelID::random);
    let serial = serial.unwrap_or_else(Serial::random);
    format!("{channel_id}-{serial}")
}

/// Generates a product key for the OEM version of 95.
///
/// Any of the parameters can be `None` to generate a random value.
pub fn generate_oem(year: Option<Year>, day: Option<Day>, oem_id: Option<OemID>) -> String {
    let year = year.unwrap_or_else(Year::random);
    let day = day.unwrap_or_else(Day::random);
    let oem_id = oem_id.unwrap_or_else(OemID::random);
    let random: i32 = thread_rng().gen_range(0..99999);
    format!("{year}{day}-OEM-{oem_id}-{random:05}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_id() {
        assert_eq!(ChannelID::new(0), Ok(ChannelID(0)));
        assert_eq!(ChannelID::new(1), Ok(ChannelID(1)));
        assert_eq!(ChannelID::new(123), Ok(ChannelID(123)));
        assert_eq!(ChannelID::new(9999), Err(ChannelIDError::OutOfRange));
        assert_eq!(ChannelID::new(777), Err(ChannelIDError::Disallowed));
    }

    #[test]
    fn test_serial() {
        assert_eq!(Serial::new(0), Ok(Serial(0)));
        assert_eq!(Serial::new(7), Ok(Serial(7)));
        assert_eq!(Serial::new(133), Ok(Serial(133)));
        assert_eq!(Serial::new(1111111), Ok(Serial(1111111)));
        assert_eq!(Serial::new(99999999), Err(SerialError::OutOfRange));
        assert_eq!(Serial::new(33), Err(SerialError::Invalid));
    }

    #[test]
    fn test_day() {
        assert_eq!(Day::new(1), Ok(Day(1)));
        assert_eq!(Day::new(123), Ok(Day(123)));
        assert_eq!(Day::new(364), Ok(Day(364)));
        assert_eq!(Day::new(0), Err(DayError::OutOfRange));
        assert_eq!(Day::new(365), Err(DayError::OutOfRange));
    }

    #[test]
    fn test_oem_id() {
        assert_eq!(OemID::new(0), Ok(OemID(0)));
        assert_eq!(OemID::new(7), Ok(OemID(7)));
        assert_eq!(OemID::new(133), Ok(OemID(133)));
        assert_eq!(OemID::new(59716), Ok(OemID(59716)));
        assert_eq!(OemID::new(100000), Err(OemIDError::OutOfRange));
        assert_eq!(OemID::new(12345), Err(OemIDError::Invalid));
    }

    #[test]
    fn test_generate_retail() {
        let _ = generate_retail(None, None);
        let key = generate_retail(Some(ChannelID(123)), Some(Serial(5971904)));
        assert_eq!(key, "123-5971904");
    }

    #[test]
    fn test_generate_oem() {
        let _ = generate_oem(None, None, None);
        let key = generate_oem(Some(Year::Year95), Some(Day(123)), Some(OemID(59716)));
        assert_eq!(&key[..18], "95123-OEM-0059716-");
    }
}
