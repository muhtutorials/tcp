use crate::utils::RingBuffer;
use bitflags::bitflags;
use core::time;
use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use std::cmp::min;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Error, ErrorKind, Result, Write};
use std::time::{Duration, Instant};
use tun::Device;

pub struct Connection {
    state: State,
    snd: SendSequence,
    rcv: ReceiveSequence,
    ip_resp_header: Ipv4Header,
    tcp_resp_header: TcpHeader,
    // todo: make it pub(crate)
    pub data_in: VecDeque<u8>,
    // unACKed by remote data
    pub data_out: VecDeque<u8>,
    timers: Timers,
    // sequence number of FIN byte if set
    is_closed: bool,
    closed_at: Option<u32>,
}

pub enum State {
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    TimeWait,
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
struct SendSequence {
    /// send unacknowledged
    una: u32,
    /// send next sequence number sent from local -> acknowledgment number received
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
struct ReceiveSequence {
    /// receive next received sequence number from remote -> acknowledgment number sent
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: u16,
    /// initial receive sequence number
    irs: u32,
}

struct Timers {
    send_times: BTreeMap<u32, Instant>,
    /// Smoothed Round Trip Time
    srtt: Duration,
}

// todo: maybe try to implement it myself
bitflags! {
    #[repr(transparent)]
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct AvailableIo: u8 {
        const READ = 0b00000001;
        const WRITE = 0b00000010;
    }
}

impl Connection {
    pub fn accept<'a>(
        dev: &mut Device,
        ip_req_header: Ipv4HeaderSlice,
        tcp_req_header: TcpHeaderSlice,
    ) -> Result<Option<Self>> {
        // only SYN packet is allowed
        if !tcp_req_header.syn() {
            return Ok(None);
        }

        let iss = 0;
        let wnd = 1024;
        let mut conn = Connection {
            state: State::SynReceived,
            snd: SendSequence {
                una: iss,
                nxt: iss,
                wnd,
                up: 0,
                wl1: 0,
                wl2: 0,
                iss,
            },
            rcv: ReceiveSequence {
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
            data_in: VecDeque::new(),
            data_out: VecDeque::new(),
            timers: Timers {
                send_times: BTreeMap::new(),
                srtt: time::Duration::from_secs(60),
            },
            is_closed: false,
            closed_at: None,
        };

        conn.tcp_resp_header.syn = true;
        conn.tcp_resp_header.ack = true;
        conn.write(dev, conn.snd.nxt, 0)?;

        Ok(Some(conn))
    }

    pub fn on_tick<'a>(&mut self, dev: &mut Device) -> Result<()> {
        let (mut head, mut tail) = self.data_out.as_slices();
        // todo: probably change "n_"'s
        let n_unacked = self.snd.nxt.wrapping_sub(self.snd.una);
        let n_unsent = self.data_out.len() - n_unacked as usize;

        // RFC: 793, section: 3.7
        // the oldest unacked seq
        // todo: look into this expression
        let elapsed = self
            .timers
            .send_times
            .range(self.snd.una..)
            .next()
            .map(|val| val.1.elapsed());

        let should_retrasmit = if let Some(elapsed) = elapsed {
            elapsed > Duration::from_secs(1) && elapsed < self.timers.srtt.mul_f32(1.5)
        } else {
            false
        };

        if should_retrasmit {
            // retransmit
            let n_resend = min(self.data_out.len(), self.snd.wnd as usize);
            if n_resend < self.snd.wnd as usize && self.is_closed {
                self.tcp_resp_header.fin = true;
                self.closed_at = Some(self.snd.una.wrapping_add(self.data_out.len() as u32));
            }
            self.write(dev, self.snd.una, n_resend)?;
        } else {
            // send new data
            if n_unsent == 0 && !self.closed_at.is_some() {
                return Ok(());
            }
            let n_allowed = self.snd.wnd as u32 - n_unacked;
            if n_allowed == 0 {
                return Ok(());
            }
            let n_send = min(n_unsent as u32, n_allowed);
            if n_send < n_allowed && self.is_closed && self.closed_at.is_none() {
                self.tcp_resp_header.fin = true;
                self.closed_at = Some(self.snd.una.wrapping_add(self.data_out.len() as u32));
            }

            self.write(dev, self.snd.nxt, n_send as usize)?;
        }
        // If no SENDs have been issued and there is no pending data to send,
        // then form a FIN segment and send it, and enter FIN-WAIT-1 state;
        // otherwise queue for processing after entering ESTABLISHED state.
        Ok(())
    }

    pub fn on_packet<'a>(
        &mut self,
        dev: &mut Device,
        ip_req_header: Ipv4HeaderSlice,
        tcp_req_header: TcpHeaderSlice,
        data: &'a [u8],
    ) -> Result<AvailableIo> {
        let mut data_len = data.len() as u32;
        if tcp_req_header.syn() {
            data_len += 1;
        }
        if tcp_req_header.fin() {
            data_len += 1;
        }

        let rcv_nxt = self.rcv.nxt.wrapping_sub(1);
        // received sequence number (incoming segment)
        let seq = tcp_req_header.sequence_number();
        let wnd_end = self.rcv.nxt.wrapping_add(self.rcv.wnd as u32);

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
        // todo: rename and refactor
        let ok = if data_len == 0 {
            if self.rcv.wnd == 0 {
                if seq != self.rcv.nxt { false } else { true }
            } else if !is_between_wrapped(rcv_nxt, seq, wnd_end) {
                false
            } else {
                true
            }
        } else {
            if self.rcv.wnd == 0 {
                false
            // The first part of this test checks to see if the beginning of the
            // segment falls in the window, the second part of the test checks to see
            // if the end of the segment falls in the window; if the segment passes
            // either part of the test it contains data in the window.
            // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
            // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
            } else if !is_between_wrapped(rcv_nxt, seq, wnd_end)
                && !is_between_wrapped(rcv_nxt, seq.wrapping_add(data_len - 1), wnd_end)
            {
                false
            } else {
                true
            }
        };

        if !ok {
            self.write(dev, self.snd.nxt, 0)?;
            return Ok(self.available_io());
        }

        // todo: why is it not in the beginning?
        if !tcp_req_header.ack() {
            if tcp_req_header.syn() {
                self.rcv.nxt = seq.wrapping_add(1);
            }
            return Ok(self.available_io());
        }

        // received acknowledgment number
        let ack = tcp_req_header.acknowledgment_number();

        if let State::SynReceived = self.state {
            // SND.UNA =< SEG.ACK =< SND.NXT
            if is_between_wrapped(
                self.snd.una.wrapping_sub(1),
                ack,
                self.snd.nxt.wrapping_add(1),
            ) {
                // Must have acked our SYN, since we detected at least one acked byte,
                // and we have only sent one byte (the SYN).
                self.state = State::Established;
            } else {
            }
        }

        if let State::Established | State::FinWait1 | State::FinWait2 = self.state {
            // A new acknowledgment (called an "acceptable ack"), is one for which
            // the inequality below holds:
            // SND.UNA < SEG.ACK =< SND.NXT
            // Takes into account integer wrapping.
            // self.snd.nxt.wrapping_add(1) makes nxt inclusive in comparison.
            // Makes is_between_wrapped more generic.
            if is_between_wrapped(self.snd.una, ack, self.snd.nxt.wrapping_add(1)) {
                self.snd.una = ack;
            }

            if let State::Established = self.state {
                // terminate connection
                self.tcp_resp_header.fin = true;
                self.state = State::FinWait1;
            }
        }

        if let State::FinWait1 = self.state {
            if self.snd.una == self.snd.iss + 2 {
                // our FIN has been ACKed
                self.state = State::FinWait2;
            }
            // Must have acked our FIN, since we detected at least one acked byte,
            // and we have only sent one byte (the FIN).
            self.state = State::FinWait2;
        }

        if let State::Established | State::FinWait1 | State::FinWait2 = self.state {
            let mut unread_data_idx = (self.rcv.nxt - seq) as usize;
            if unread_data_idx > data_len as usize {
                // We must have received a retransmitted FIN we have already seen.
                // rcv.nxt points beyond FIN, but fin is not in data.
                unread_data_idx = 0;
            }
            self.data_in.extend(&data[unread_data_idx..]);

            // Once the TCP takes responsibility for the data it advances
            // RCV.NXT over the data accepted, and adjusts RCV.WND as
            // appropriate to the current buffer availability. The total of
            // RCV.NXT and RCV.WND should not be reduced.
            self.rcv.nxt = seq
                .wrapping_add(data_len)
                .wrapping_add(if tcp_req_header.fin() { 1 } else { 0 });

            // send an acknowledgment of the form:
            // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
            self.write(dev, self.snd.nxt, 0)?;
        }

        if tcp_req_header.fin() {
            match self.state {
                State::FinWait2 => {
                    // done with the connection
                    self.write(dev, self.snd.nxt, 0)?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
            }
        }

        Ok(self.available_io())
    }

    fn write<'a>(&mut self, dev: &mut Device, seq_num: u32, limit: usize) -> Result<usize> {
        let mut buf = [0u8; 4096];

        self.tcp_resp_header.sequence_number = seq_num;
        self.tcp_resp_header.acknowledgment_number = self.rcv.nxt;

        let (mut head, mut tail) = self.data_out.as_slices();
        let offset = seq_num.wrapping_sub(self.snd.una);
        if head.len() >= offset as usize {
            head = &head[offset as usize..]
        } else {
            let skipped = head.len();
            head = &[];
            tail = &tail[(offset as usize - skipped)..]
        }

        let mut limit = min(limit, head.len() + tail.len());
        let size = min(
            buf.len(),
            self.ip_resp_header.header_len() + self.tcp_resp_header.header_len() + limit,
        );

        self.ip_resp_header
            .set_payload_len(size - self.ip_resp_header.header_len())
            .map_err(|err| Error::new(ErrorKind::InvalidInput, err))?;

        self.tcp_resp_header.checksum = self
            .tcp_resp_header
            .calc_checksum_ipv4(&self.ip_resp_header, &[])
            .expect("failed to compute checksum");

        let mut unwritten = &mut buf[..];
        self.ip_resp_header.write(&mut unwritten)?;
        self.tcp_resp_header.write(&mut unwritten)?;
        let n_payload_bytes = {
            let mut written = 0;
            limit = min(limit, head.len() + tail.len());

            let head_end = min(limit, head.len());
            written += unwritten.write(&head[..head_end])?;
            limit -= written;

            let tail_end = min(limit, tail.len());
            written += unwritten.write(&head[..tail_end])?;

            written
        };

        let mut next_seq_num = seq_num.wrapping_add(n_payload_bytes as u32);
        if self.tcp_resp_header.syn {
            next_seq_num = next_seq_num.wrapping_add(1);
            self.tcp_resp_header.syn = false;
        }
        if self.tcp_resp_header.fin {
            next_seq_num = next_seq_num.wrapping_add(1);
            self.tcp_resp_header.fin = false;
        }

        if wrapping_less_than(self.snd.nxt, next_seq_num) {
            self.snd.nxt = next_seq_num;
        }

        self.timers.send_times.insert(seq_num, Instant::now());

        let unwritten_len = unwritten.len();
        let data_len = buf.len() - unwritten_len;
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
        self.write(dev, self.snd.nxt, 0)?;
        Ok(())
    }

    pub(crate) fn is_received_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            return true;
        }
        false
    }

    fn available_io(&self) -> AvailableIo {
        let mut aio = AvailableIo::empty();
        if self.is_received_closed() || !self.data_in.is_empty() {
            aio.insert(AvailableIo::READ);
        }
        aio
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        self.is_closed = true;
        match self.state {
            State::SynReceived | State::Established => {
                self.state = State::FinWait1;
            }
            State::FinWait1 | State::FinWait2 => {}
            _ => return Err(Error::new(ErrorKind::NotConnected, "already closing")),
        }
        Ok(())
    }
}

impl State {
    fn is_established(&self) -> bool {
        match self {
            State::SynReceived => false,
            _ => true,
        }
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

fn wrapping_less_than(lhs: u32, rhs: u32) -> bool {
    // From RFC1323:
    // TCP determines if a data segment is "old" or "new" by testing
    // whether its sequence number is within 2**31 bytes of the left edge
    // of the window, and if it is not, discarding the data as "old". To
    // ensure that new data is never mistakenly considered old and vice-
    // versa, the left edge of the sender's window has to be at most
    // 2**31 away from the right edge of the receiver's window.
    lhs.wrapping_sub(rhs) > (1 << 31)
}

// fn is_between_wrapped(start: u32, between: u32, end: u32) -> bool {
//     wrapping_less_than(start, between) && wrapping_less_than(between, end)
// }
