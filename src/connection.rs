use crate::{AvailableIo, IoFlag};
use core::time;
use etherparse::{IpNumber, Ipv4Header, Ipv4HeaderSlice, TcpHeader, TcpHeaderSlice};
use std::cmp::min;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Cursor, Error, ErrorKind, Result, Write};
use std::time::{Duration, Instant};
use tun::Device;

pub struct Connection {
    state: State,
    send: SendVars,
    recv: ReceiveVars,
    ip_resp_header: Ipv4Header,
    tcp_resp_header: TcpHeader,
    // data sent to us by remote
    pub(crate) data_in: VecDeque<u8>,
    // data we sent which hasn't been acked by remote yet
    pub(crate) data_out: VecDeque<u8>,
    timers: Timers,
    is_closed: bool,
    // sequence number of FIN byte if set
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
struct SendVars {
    /// send unacknowledged
    unacked_seq_num: u32,
    /// send next sequence number sent from local -> acknowledgment number received
    seq_num: u32,
    /// send window
    window: u16,
    /// initial send sequence number
    init_seq_num: u32,
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
struct ReceiveVars {
    /// receive next received sequence number from remote -> acknowledgment number sent
    seq_num: u32,
    /// receive window
    window: u16,
    /// initial receive sequence number
    init_seq_num: u32,
}

struct Timers {
    // <sequence number, time it was sent>
    send_times: BTreeMap<u32, Instant>,
    /// Smoothed Round Trip Time
    smoothed_round_trip_time: Duration,
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

        let init_seq_num = 0;
        let window = 1024;
        let mut conn = Connection {
            state: State::SynReceived,
            send: SendVars {
                unacked_seq_num: init_seq_num,
                seq_num: init_seq_num,
                window,
                init_seq_num,
            },
            recv: ReceiveVars {
                seq_num: tcp_req_header.sequence_number() + 1,
                window: tcp_req_header.window_size(),
                init_seq_num: tcp_req_header.sequence_number(),
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
                init_seq_num,
                window,
            ),
            data_in: VecDeque::new(),
            data_out: VecDeque::new(),
            timers: Timers {
                send_times: BTreeMap::new(),
                smoothed_round_trip_time: time::Duration::from_secs(60),
            },
            is_closed: false,
            closed_at: None,
        };

        conn.tcp_resp_header.syn = true;
        conn.tcp_resp_header.ack = true;
        conn.write(dev, conn.send.seq_num, 0)?;

        Ok(Some(conn))
    }

    pub fn tick<'a>(&mut self, dev: &mut Device) -> Result<()> {
        if let State::FinWait2 | State::TimeWait = self.state {
            // we have shutdown our write side and the other side acked, no need to (re)transmit anything
            return Ok(());
        }
        let n_unacked = self
            .closed_at
            .unwrap_or(self.send.seq_num)
            .wrapping_sub(self.send.unacked_seq_num);
        let n_unsent = self.data_out.len() - n_unacked as usize;

        // RFC: 793, section: 3.7
        // the oldest unacked seq
        let elapsed = self
            .timers
            .send_times
            .range(self.send.unacked_seq_num..)
            .next()
            .map(|val| val.1.elapsed());

        let should_retransmit = if let Some(elapsed) = elapsed {
            elapsed > Duration::from_secs(1) && elapsed > self.timers.smoothed_round_trip_time.mul_f32(1.5)
        } else {
            false
        };

        if should_retransmit {
            let n_resend = min(self.data_out.len(), self.send.window as usize);
            if n_resend < self.send.window as usize && self.is_closed {
                self.tcp_resp_header.fin = true;
                self.closed_at = Some(self.send.unacked_seq_num.wrapping_add(self.data_out.len() as u32));
            }
            self.write(dev, self.send.unacked_seq_num, n_resend)?;
        } else {
            // send new data
            if n_unsent == 0 && self.closed_at.is_some() {
                return Ok(());
            }
            let n_allowed = self.send.window as u32 - n_unacked;
            if n_allowed == 0 {
                return Ok(());
            }
            let n_send = min(n_unsent as u32, n_allowed);
            if n_send < n_allowed && self.is_closed && self.closed_at.is_none() {
                self.tcp_resp_header.fin = true;
                self.closed_at = Some(self.send.unacked_seq_num.wrapping_add(self.data_out.len() as u32));
            }

            self.write(dev, self.send.seq_num, n_send as usize)?;
        }
        // If no SENDs have been issued and there is no pending data to send,
        // then form a FIN segment and send it, and enter FIN-WAIT-1 state;
        // otherwise queue for processing after entering ESTABLISHED state.
        Ok(())
    }

    pub fn handle_packet<'a>(
        &mut self,
        dev: &mut Device,
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

        let recv_seq_num = self.recv.seq_num.wrapping_sub(1);
        // received sequence number (incoming segment)
        let incoming_seq_num = tcp_req_header.sequence_number();
        let window_end = self.recv.seq_num.wrapping_add(self.recv.window as u32);

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
        // acceptable incoming sequence number
        let acceptable = if data_len == 0 {
            if self.recv.window == 0 {
                if incoming_seq_num != self.recv.seq_num { false } else { true }
            } else if !is_between_wrapped(recv_seq_num, incoming_seq_num, window_end) {
                false
            } else {
                true
            }
        } else {
            if self.recv.window == 0 {
                false
            // The first part of this test checks to see if the beginning of the
            // segment falls in the window, the second part of the test checks to see
            // if the end of the segment falls in the window; if the segment passes
            // either part of the test it contains data in the window.
            // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
            // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
            } else if !is_between_wrapped(recv_seq_num, incoming_seq_num, window_end)
                && !is_between_wrapped(recv_seq_num, incoming_seq_num.wrapping_add(data_len - 1), window_end)
            {
                false
            } else {
                true
            }
        };

        if !acceptable {
            self.write(dev, self.send.seq_num, 0)?;
            return Ok(self.available_io());
        }

        if !tcp_req_header.ack() {
            if tcp_req_header.syn() {
                self.recv.seq_num = incoming_seq_num.wrapping_add(1);
            }
            return Ok(self.available_io());
        }

        // received acknowledgment number
        let ack = tcp_req_header.acknowledgment_number();

        if let State::SynReceived = self.state {
            // SND.UNA =< SEG.ACK =< SND.NXT
            if is_between_wrapped(
                self.send.unacked_seq_num.wrapping_sub(1),
                ack,
                self.send.seq_num.wrapping_add(1),
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
            if is_between_wrapped(self.send.unacked_seq_num, ack, self.send.seq_num.wrapping_add(1)) {
                if !self.data_out.is_empty() {
                    let data_start = if self.send.unacked_seq_num == self.send.init_seq_num {
                        // snd.una hasn't been updated yet with ACK for our SYN, so data starts just beyond it
                        self.send.unacked_seq_num.wrapping_add(1)
                    } else {
                        self.send.unacked_seq_num
                    };
                    let acked_data_end =
                        min(ack.wrapping_sub(data_start) as usize, self.data_out.len());

                    self.data_out.drain(..acked_data_end);

                    self.timers.send_times.retain(|seq, sent| {
                        if is_between_wrapped(self.send.unacked_seq_num, *seq, ack) {
                            let round_trip_time = sent.elapsed();
                            // SRTT = ( ALPHA * SRTT ) + ((1-ALPHA) * RTT)
                            self.timers.smoothed_round_trip_time =
                                self.timers.smoothed_round_trip_time.mul_f64(0.8) + round_trip_time.mul_f64(1.0 - 0.8);
                            return false;
                        }
                        true
                    });
                }
                self.send.unacked_seq_num = ack;
            }
        }

        if let State::FinWait1 = self.state {
            if let Some(closed_at) = self.closed_at {
                if self.send.unacked_seq_num == closed_at.wrapping_add(1) {
                    // our FIN has been ACKed
                    self.state = State::FinWait2;
                }
            }
        }

        if !data.is_empty() {
            if let State::Established | State::FinWait1 | State::FinWait2 = self.state {
                let mut unread_data_idx = self.recv.seq_num.wrapping_sub(incoming_seq_num) as usize;
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
                self.recv.seq_num = incoming_seq_num.wrapping_add(data_len);

                // send an acknowledgment of the form:
                // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
                self.write(dev, self.send.seq_num, 0)?;
            }
        }

        if tcp_req_header.fin() {
            match self.state {
                State::FinWait2 => {
                    // done with the connection
                    self.recv.seq_num = incoming_seq_num.wrapping_add(1);
                    self.write(dev, self.send.seq_num, 0)?;
                    self.state = State::TimeWait;
                }
                _ => unimplemented!(),
            }
        }

        Ok(self.available_io())
    }

    fn write<'a>(&mut self, dev: &mut Device, seq_num: u32, mut limit: usize) -> Result<usize> {
        let buf = [0u8; 4096];
        let mut buf = Cursor::new(buf);
        let buf_len = buf.get_ref().len();

        self.tcp_resp_header.sequence_number = seq_num;
        self.tcp_resp_header.acknowledgment_number = self.recv.seq_num;

        let mut offset = seq_num.wrapping_sub(self.send.unacked_seq_num);
        if let Some(closed_at) = self.closed_at {
            if seq_num == closed_at.wrapping_add(1) {
                offset = 0;
                limit = 0;
            }
        }

        let (mut head, mut tail) = self.data_out.as_slices();
        if head.len() >= offset as usize {
            head = &head[offset as usize..]
        } else {
            let skipped = head.len();
            head = &[];
            tail = &tail[(offset as usize - skipped)..]
        }

        let mut limit = min(limit, head.len() + tail.len());
        let size = min(
            buf_len,
            self.ip_resp_header.header_len() + self.tcp_resp_header.header_len() + limit,
        );

        self.ip_resp_header
            .set_payload_len(size - self.ip_resp_header.header_len())
            .map_err(|err| Error::new(ErrorKind::InvalidInput, err))?;

        self.ip_resp_header.write(&mut buf)?;
        let ip_header_end_idx = buf.position() as usize;

        // postpone writing the tcp header because we need the ip payload
        // as one contiguous slice to calculate the tcp checksum
        buf.set_position((ip_header_end_idx + self.tcp_resp_header.header_len()) as u64);
        let tcp_header_end_idx = buf.position() as usize;

        let n_payload_bytes = {
            let mut written = 0;

            let head_end = min(limit, head.len());
            written += buf.write(&head[..head_end])?;
            limit -= written;

            let tail_end = min(limit, tail.len());
            written += buf.write(&tail[..tail_end])?;

            written
        };

        let payload_end_idx = buf.position() as usize;

        let mut buf = buf.get_mut();

        // finally we can calculate the tcp checksum and write out the tcp header
        self.tcp_resp_header.checksum = self
            .tcp_resp_header
            .calc_checksum_ipv4(
                &self.ip_resp_header,
                &mut buf[ip_header_end_idx..payload_end_idx],
            )
            .expect("failed to compute checksum");

        let mut tcp_header_buf = &mut buf[ip_header_end_idx..tcp_header_end_idx];
        // tcp data has already been written, so we write just tcp header with calculated checksum
        self.tcp_resp_header.write(&mut tcp_header_buf)?;

        let mut next_seq_num = seq_num.wrapping_add(n_payload_bytes as u32);
        if self.tcp_resp_header.syn {
            next_seq_num = next_seq_num.wrapping_add(1);
            self.tcp_resp_header.syn = false;
        }
        if self.tcp_resp_header.fin {
            next_seq_num = next_seq_num.wrapping_add(1);
            self.tcp_resp_header.fin = false;
        }

        if wrapping_less_than(self.send.seq_num, next_seq_num) {
            self.send.seq_num = next_seq_num;
        }

        self.timers.send_times.insert(seq_num, Instant::now());

        dev.send(&buf[..payload_end_idx])?;

        Ok(n_payload_bytes)
    }

    fn reset_connection(&mut self, dev: &mut Device) -> Result<()> {
        // If the incoming segment has an ACK field, the reset takes its
        // sequence number from the ACK field of the segment, otherwise the
        // reset has sequence number zero and the ACK field is set to the sum
        // of the sequence number and segment length of the incoming segment.
        // The connection remains in the same state.
        //
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
        self.write(dev, self.send.seq_num, 0)?;
        Ok(())
    }

    pub(crate) fn is_received_closed(&self) -> bool {
        if let State::TimeWait = self.state {
            return true;
        }
        false
    }

    fn available_io(&self) -> AvailableIo {
        let mut aio = AvailableIo::new();
        if self.is_received_closed() || !self.data_in.is_empty() {
            aio.set(IoFlag::Read);
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
