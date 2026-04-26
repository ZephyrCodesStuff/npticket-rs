pub enum TicketData {
    Empty(),
    U32(u32),
    U64(u64),
    Time(u64),
    Binary(Vec<u8>),
    BString(Vec<u8>),
    Blob(u8, Vec<TicketData>),
}

impl TicketData {
    /// The type id of the ticket data.
    pub fn id(&self) -> u16 {
        match self {
            TicketData::Empty() => 0,
            TicketData::U32(_) => 1,
            TicketData::U64(_) => 2,
            TicketData::BString(_) => 4,
            TicketData::Time(_) => 7,
            TicketData::Binary(_) => 8,
            TicketData::Blob(id, _) => 0x3000 | (*id as u16),
        }
    }

    /// The length of the ticket data.
    pub fn len(&self) -> u16 {
        match self {
            TicketData::Empty() => 0,
            TicketData::U32(_) => 4,
            TicketData::U64(_) => 8,
            TicketData::BString(string_data) => string_data.len() as u16,
            TicketData::Time(_) => 8,
            TicketData::Binary(binary_data) => binary_data.len() as u16,
            TicketData::Blob(_, sdata) => sdata.iter().map(|x| x.len() + 4).sum(),
        }
    }

    /// Write the ticket data to a byte vector.
    pub fn write(&self, dest: &mut Vec<u8>) {
        dest.extend(&self.id().to_be_bytes());
        dest.extend(&self.len().to_be_bytes());

        match self {
            TicketData::Empty() => {}
            TicketData::U32(value) => dest.extend(&value.to_be_bytes()),
            TicketData::U64(value) => dest.extend(&value.to_be_bytes()),
            TicketData::BString(string_data) => dest.extend(string_data),
            TicketData::Time(time) => dest.extend(&time.to_be_bytes()),
            TicketData::Binary(binary_data) => dest.extend(binary_data),
            TicketData::Blob(_, sdata) => {
                for sub in sdata {
                    sub.write(dest);
                }
            }
        }
    }
}
