use traits::Into;
use traits::TryInto;
use array::SpanTrait;

#[derive(Copy, Drop)]
struct DateTime {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8
}


#[generate_trait]
impl TimeDecodeImpl of TimeDecodeTrait {
    fn from_der_to_timestamp(self: Span<u8>) -> u32 {
        let mut dt = DateTime {
            year: 0,
            month: 0,
            day: 0,
            hour: 0,
            minute: 0,
            second: 0
        };

        let mut offset = 0;
        if self.len() == 13 {
            // YYMMDDhhmmssZ format
            let first_digit: u8 = *self.at(0) - 48;
            if first_digit < 5 {
                dt.year = 2000;
            } else {
                dt.year = 1900;
            }
        } else {
            // YYYYMMDDhhmmssZ format
            dt.year = ((*self.at(0) - 48).into() * 1000_u16 + (*self.at(1) - 48).into() * 100_u16).try_into().unwrap();
            offset = 2;
        }

        dt.year += ((*self.at(offset) - 48) * 10 + (*self.at(offset + 1) - 48)).try_into().unwrap();
        dt.month = (*self.at(offset + 2) - 48) * 10 + (*self.at(offset + 3) - 48);
        dt.day = (*self.at(offset + 4) - 48) * 10 + (*self.at(offset + 5) - 48);
        dt.hour = (*self.at(offset + 6) - 48) * 10 + (*self.at(offset + 7) - 48);
        dt.minute = (*self.at(offset + 8) - 48) * 10 + (*self.at(offset + 9) - 48);
        dt.second = (*self.at(offset + 10) - 48) * 10 + (*self.at(offset + 11) - 48);

        date_time_to_timestamp(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)
    }

    fn from_iso_to_timestamp(self: Span<u8>) -> u32 {
        assert(self.len() == 20, 'Invalid ISO string length');

        let mut dt = DateTime {
            year: 0,
            month: 0,
            day: 0,
            hour: 0,
            minute: 0,
            second: 0
        };

        // Parse YYYY-MM-DDTHH:mm:ssZ format
        dt.year = ((*self.at(0) - 48).into() * 1000_u16 + (*self.at(1) - 48).into() * 100_u16 + 
            (*self.at(2) - 48).into() * 10_u16 + (*self.at(3) - 48).into()).try_into().unwrap();
        dt.month = (*self.at(5) - 48) * 10 + (*self.at(6) - 48);
        dt.day = (*self.at(8) - 48) * 10 + (*self.at(9) - 48);
        dt.hour = (*self.at(11) - 48) * 10 + (*self.at(12) - 48);
        dt.minute = (*self.at(14) - 48) * 10 + (*self.at(15) - 48);
        dt.second = (*self.at(17) - 48) * 10 + (*self.at(18) - 48);

        date_time_to_timestamp(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)
    }
}

fn date_to_epoch_day(year: u16, month: u8, day: u8) -> u32 {
    let mut year: u32 = year.into();
    if month < 3 {
        year = year - 1;
    }
    let doy: u32 = ((62719 * ((month.into() + 9) % 12) + 769) / 2048) + day.into();
    let yoe: u32 = year % 400;
    let doe: u32 = yoe * 365 + (yoe / 4) + doy - (yoe / 100);
    ((year / 400) * 146097 + doe - 719469).into()
}

fn date_time_to_timestamp(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> u32 {
    date_to_epoch_day(year, month, day) * 86400 + hour.into() * 3600 + minute.into() * 60 + second.into()
}
