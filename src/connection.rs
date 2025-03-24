use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use std::cmp::min;
use std::io::{Error, ErrorKind, Result, Write};
use tun::Device;

pub struct Connection {
    state: State,
    snd: SendSequenceSpace,
    rcv: ReceiveSequenceSpace,
    ip_resp_header: Ipv4Header,
    tcp_resp_header: TcpHeader,
}

pub enum State {
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    Closing,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match self {
            State::SynReceived => false,
            State::Established | State::FinWait1 | State::FinWait2 | State::Closing => true,
        }
    }
}

///    Send Sequence Space (RFC: 793, section: 3.2)
///
///      1         2          3          4
/// ----------|----------|----------|----------
///        SND.UNA    SND.NXT    SND.UNA
///                             +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next (acknowledgment number received -> sequence number sent)
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: u16,
    /// segment sequence number used for last window update
    wl1: u32,
    /// segment acknowledgment number used for last window update
    wl2: u32,
    /// initial send sequence number
    iss: u32,
}

///      Receive Sequence Space
///
///      1          2          3
/// ----------|----------|----------
///        RCV.NXT    RCV.NXT
///                  +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
struct ReceiveSequenceSpace {
    /// receive next (sequence number received -> acknowledgment number sent)
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: u16,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        dev: &mut Device,
        ip_req_header: Ipv4HeaderSlice,
        tcp_req_header: TcpHeaderSlice,
    ) -> Result<Option<Self>> {
        if !tcp_req_header.syn() {
            // only SYN packet is expected
            return Ok(None);
        }

        let iss = 0;
        let wnd = 10;
        let mut conn = Connection {
            state: State::SynReceived,
            snd: SendSequenceSpace {
                una: iss,
                nxt: iss,
                wnd,
                up: 0,
                wl1: 0,
                wl2: 0,
                iss,
            },
            rcv: ReceiveSequenceSpace {
                nxt: tcp_req_header.sequence_number() + 1,
                wnd: tcp_req_header.window_size(),
                up: 0,
                irs: tcp_req_header.sequence_number(),
            },
            ip_resp_header: Ipv4Header::new(
                0, // set later
                64,
                IpNumber::TCP,
                ip_req_header.destination(),
                ip_req_header.source(),
            )
            .map_err(|err| Error::new(ErrorKind::InvalidInput, err))?,
            tcp_resp_header: TcpHeader::new(
                tcp_req_header.destination_port(),
                tcp_req_header.source_port(),
                iss,
                wnd,
            ),
        };

        conn.tcp_resp_header.syn = true;
        conn.tcp_resp_header.ack = true;
        conn.write(dev, &[])?;

        Ok(Some(conn))
    }

    pub fn on_packet<'a>(
        &mut self,
        dev: &mut Device,
        ip_req_header: Ipv4HeaderSlice,
        tcp_req_header: TcpHeaderSlice,
        data: &'a [u8],
    ) -> Result<()> {
        // SND.UNA = oldest unacknowledged sequence number
        //
        // SND.NXT = next sequence number to be sent
        //
        // SEG.ACK = acknowledgment from the receiving TCP (next sequence
        // number expected by the receiving TCP)
        //
        // SEG.SEQ = first sequence number of a segment
        //
        // SEG.LEN = the number of octets occupied by the data in the segment
        // (counting SYN and FIN)
        //
        // SEG.SEQ+SEG.LEN-1 = last sequence number of a segment
        let rcv_nxt = self.rcv.nxt.wrapping_sub(1);
        let req_seq_num = tcp_req_header.sequence_number();
        let rcv_nxt_plus_wnd = self.rcv.nxt.wrapping_add(self.rcv.wnd as u32);
        let mut data_len = data.len() as u32;
        if tcp_req_header.syn() {
            data_len += 1;
        }
        if tcp_req_header.fin() {
            data_len += 1;
        }
        //   Segment Receive  Test
        //   Length  Window
        //   ------- -------  -------------------------------------------
        //
        //      0       0     SEG.SEQ = RCV.NXT
        //
        //      0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //
        //     >0       0     not acceptable
        //
        //     >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
        //                 or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        // zero-length segment has separate rules for acceptance
        if data_len == 0 && !tcp_req_header.syn() && !tcp_req_header.fin() {
            if self.rcv.wnd == 0 {
                if req_seq_num != self.rcv.nxt {
                    return Ok(());
                }
            } else if !is_between_wrapped(rcv_nxt, req_seq_num, rcv_nxt_plus_wnd) {
                return Ok(());
            }
        } else {
            if self.rcv.wnd == 0 {
                return Ok(());
            // The first part of this test checks to see if the beginning of the
            // segment falls in the window, the second part of the test checks to see
            // if the end of the segment falls in the window; if the segment passes
            // either part of the test it contains data in the window.
            // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
            // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
            } else if !is_between_wrapped(rcv_nxt, req_seq_num, rcv_nxt_plus_wnd)
                && !is_between_wrapped(
                    rcv_nxt,
                    req_seq_num.wrapping_add(data_len - 1),
                    rcv_nxt_plus_wnd,
                )
            {
                return Ok(());
            }
        }

        self.rcv.nxt = req_seq_num.wrapping_add(data_len);

        if !tcp_req_header.ack() {
            return Ok(());
        }

        let rcv_ack = tcp_req_header.acknowledgment_number();

        if let State::SynReceived = self.state {
            // SND.UNA =< SEG.ACK =< SND.NXT
            if !is_between_wrapped(
                self.snd.una.wrapping_sub(1),
                rcv_ack,
                self.snd.nxt.wrapping_add(1),
            ) {
                // Must have acked our SYN, since we detected at least one acked byte,
                // and we have only sent one byte (the SYN).
                self.state = State::Established;
            } else {
            }
        }

        match self.state {
            State::SynReceived => unreachable!(),
            State::Established => {
                // A new acknowledgment (called an "acceptable ack"), is one for which
                // the inequality below holds:
                // SND.UNA < SEG.ACK =< SND.NXT
                // Takes into account integer wrapping.
                // self.snd.nxt.wrapping_add(1) makes nxt inclusive in comparison.
                // Makes is_between_wrapped more generic.
                if !is_between_wrapped(self.snd.una, rcv_ack, self.snd.nxt.wrapping_add(1)) {
                    return Ok(());
                }
                self.snd.una = rcv_ack;
                assert!(data.is_empty());

                // terminate connection
                self.tcp_resp_header.fin = true;
                self.write(dev, &[])?;
                self.state = State::FinWait1;
            }
            State::FinWait1 => {
                if !data.is_empty() || !tcp_req_header.fin() {
                    unimplemented!()
                }
                // Must have acked our FIN, since we detected at least one acked byte,
                // and we have only sent one byte (the FIN).
                self.state = State::FinWait2;
            }
            State::FinWait2 => {
                if !data.is_empty() || !tcp_req_header.fin() {
                    unimplemented!()
                }
                self.tcp_resp_header.fin = false;
                self.write(dev, &[])?;
                self.state = State::Closing;
            }
            State::Closing => {}
        }
        Ok(())
    }

    fn write<'a>(&mut self, dev: &mut Device, payload: &'a [u8]) -> Result<usize> {
        let mut buf = [0u8; 4096];

        self.tcp_resp_header.sequence_number = self.snd.nxt;
        self.tcp_resp_header.acknowledgment_number = self.rcv.nxt;

        let size = min(
            buf.len(),
            self.ip_resp_header.header_len() + self.tcp_resp_header.header_len() + payload.len(),
        );

        self.ip_resp_header
            .set_payload_len(size)
            .map_err(|err| Error::new(ErrorKind::InvalidInput, err))?;
        self.tcp_resp_header.checksum = self
            .tcp_resp_header
            .calc_checksum_ipv4(&self.ip_resp_header, &[])
            .expect("failed to compute checksum");

        let mut unwritten = &mut buf[..];
        self.ip_resp_header.write(&mut unwritten)?;
        self.tcp_resp_header.write(&mut unwritten)?;
        let n_payload_bytes = unwritten.write(payload)?;

        self.snd.nxt = self.snd.nxt.wrapping_add(n_payload_bytes as u32);
        if self.tcp_resp_header.syn {
            self.snd.nxt = self.snd.nxt.wrapping_add(1);
            self.tcp_resp_header.syn = false;
        }
        if self.tcp_resp_header.fin {
            self.snd.nxt = self.snd.nxt.wrapping_add(1);
            self.tcp_resp_header.fin = false;
        }

        let data_len = buf.len() - unwritten.len();
        dev.send(&buf[..data_len])?;

        Ok(n_payload_bytes)
    }

    fn send_rst(&mut self, dev: &mut Device) -> Result<()> {
        // todo: fix sequence numbers
        // If the incoming segment has an ACK field, the reset takes its
        // sequence number from the ACK field of the segment, otherwise the
        // reset has sequence number zero and the ACK field is set to the sum
        // of the sequence number and segment length of the incoming segment.
        // The connection remains in the same state.
        //
        // todo: handle synchronized RST
        // If the connection is in a synchronized state (ESTABLISHED,
        // FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT),
        // any unacceptable segment (out of window sequence number or
        // unacceptable acknowledgment number) must elicit only an empty
        // acknowledgment segment containing the current send-sequence number
        // and an acknowledgment indicating the next sequence number expected
        // to be received, and the connection remains in the same state.
        self.tcp_resp_header.rst = true;
        self.tcp_resp_header.sequence_number = 0;
        self.tcp_resp_header.acknowledgment_number = 0;
        self.write(dev, &[])?;
        Ok(())
    }
}

fn is_between_wrapped(start: u32, between: u32, end: u32) -> bool {
    if start == between {
        return false;
    }
    // if start < between then end shouldn't be between them:
    // 0...start...between...end...u32::MAX -> OK
    // 0...end...start...between...u32::MAX -> OK
    // 0...start...end...between...u32::MAX -> not OK
    if start < between {
        if start <= end && end <= between {
            return false;
        }
        // if between < start then end should be between them:
        // 0...between...end...start...u32::MAX -> OK
        // 0...end...between...start...u32::MAX -> not OK
        // 0...between...start...end...u32::MAX -> not OK
    } else {
        if !(between < end && end < start) {
            return false;
        }
    }
    true
}
