use crate::models::{RibGenericEntries, Safi, TableDumpV2Type};
use crate::parser::ReadUtils;
use crate::ParserError;
use bytes::{Buf, Bytes};
use log::{debug, warn};

use super::rib_afi_entries::parse_rib_entry;

/// RIB Generic entries per RFC 6396 Section 4.3.4.
///
/// The RIB_GENERIC header consists of an AFI, SAFI, and a single NLRI entry.
/// The NLRI information is specific to the AFI and SAFI values.
pub fn parse_rib_generic_entries(
    data: &mut Bytes,
    rib_type: TableDumpV2Type,
) -> Result<RibGenericEntries, ParserError> {
    let is_add_path = matches!(rib_type, TableDumpV2Type::RibGenericAddPath);

    let sequence_number = data.read_u32()?;
    let afi = data.read_afi()?;
    let safi = data.read_safi()?;

    let nlri = if safi == Safi::MplsVpn {
        data.read_vpn_nlri_prefix(&afi, is_add_path)?
    } else {
        data.read_nlri_prefix(&afi, is_add_path)?
    };

    let entry_count = data.read_u16()?;
    debug!(
        "RIB_GENERIC: afi={:?}, safi={:?}, prefix={}, entries={}",
        afi, safi, nlri, entry_count
    );
    // Pre-allocate cautiously to avoid overflow/OOM with malformed inputs
    let min_entry_size =
        2 /*peer_index*/ + 4 /*time*/ + 2 /*attr_len*/ + if is_add_path { 4 } else { 0 };
    let max_possible = data.remaining() / min_entry_size;
    let reserve = (entry_count as usize).min(max_possible).saturating_mul(2);
    let mut rib_entries = Vec::with_capacity(reserve);

    for _i in 0..entry_count {
        let entry = match parse_rib_entry(data, is_add_path, &afi, &safi, nlri) {
            Ok(entry) => entry,
            Err(e) => {
                warn!("early break due to error {}", e);
                break;
            }
        };
        rib_entries.push(entry);
    }

    Ok(RibGenericEntries {
        sequence_number,
        afi,
        safi,
        nlri,
        rib_entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Afi;
    use bytes::BufMut;

    #[test]
    fn test_parse_rib_generic_vpn_ipv4() -> Result<(), ParserError> {
        let mut bytes = bytes::BytesMut::new();

        // Sequence number
        bytes.put_u32(1);

        // AFI: IPv4 (1)
        bytes.put_u16(1);

        // SAFI: MPLS VPN (128)
        bytes.put_u8(128);

        // VPN NLRI: length (1 byte) + MPLS label (3 bytes) + RD (8 bytes) + IP prefix
        // For a /24 prefix: 24 (MPLS) + 64 (RD) + 24 (prefix) = 112 bits
        bytes.put_u8(112);

        // MPLS label (3 bytes) - bottom of stack
        bytes.put_u8(0x00);
        bytes.put_u8(0x00);
        bytes.put_u8(0x01); // label with bottom-of-stack bit

        // Route Distinguisher (8 bytes)
        // Type 0: 2-byte admin + 4-byte assigned
        bytes.put_u16(0); // RD type
        bytes.put_u16(65000); // admin (ASN)
        bytes.put_u32(100); // assigned number

        // IP prefix: 192.0.2.0/24 (3 bytes for /24)
        bytes.put_u8(192);
        bytes.put_u8(0);
        bytes.put_u8(2);

        // Entry count: 0 (no RIB entries for this test)
        bytes.put_u16(0);

        let mut data = bytes.freeze();
        let result = parse_rib_generic_entries(&mut data, TableDumpV2Type::RibGeneric)?;

        assert_eq!(result.sequence_number, 1);
        assert_eq!(result.afi, Afi::Ipv4);
        assert_eq!(result.safi, Safi::MplsVpn);
        assert!(result.nlri.rd.is_some());
        assert_eq!(result.nlri.prefix.to_string(), "192.0.2.0/24");
        assert_eq!(result.rib_entries.len(), 0);

        Ok(())
    }
}
