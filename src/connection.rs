use crate::{AvailableIo, IoFlag};
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
    // sequence number of FIN byte
    closed_at: Option<u32>,
}

#[derive(Debug)]
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
#[derive(Debug)]
struct SendVars {
    /// sequence number of unacknowledged data
    unacked_seq_num: u32,
    /// sequence number sent from local = acknowledgment number + data length received from remote
    seq_num: u32,
    window: u16,
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
#[derive(Debug)]
struct ReceiveVars {
    /// received sequence number from remote = acknowledgment number + data length sent from local
    seq_num: u32,
    // TCP provides a means for the receiver to govern the amount of data
    // sent by the sender. This is achieved by returning a "window" with
    // every ACK indicating a range of acceptable sequence numbers beyond
    // the last segment successfully received. The window indicates an
    // allowed number of octets that the sender may transmit before
    // receiving further permission.
    window: u16,
}

struct Timers {
    // <sequence number, time it was sent>
    send_times: BTreeMap<u32, Instant>,
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
        println!("Connection.accept => recv.seq_num: {:?}", tcp_req_header.sequence_number());

        let init_seq_num = 0;
        let window = 1024;
        let mut conn = Connection {
            state: State::SynReceived,
            send: SendVars {
                unacked_seq_num: init_seq_num,
                seq_num: init_seq_num,
                window: tcp_req_header.window_size(),
                init_seq_num,
            },
            recv: ReceiveVars {
                seq_num: tcp_req_header.sequence_number() + 1,
                window,
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
                smoothed_round_trip_time: Duration::from_secs(60),
            },
            is_closed: false,
            closed_at: None,
        };

        conn.tcp_resp_header.syn = true;
        conn.tcp_resp_header.ack = true;
        conn.write(dev, conn.send.seq_num, 0)?;

        Ok(Some(conn))
    }

    fn write<'a>(&mut self, dev: &mut Device, seq_num: u32, mut limit: usize) -> Result<usize> {
        let buf = [0u8; 4096];
        let mut buf = Cursor::new(buf);
        let buf_len = buf.get_ref().len();

        self.tcp_resp_header.sequence_number = seq_num;
        self.tcp_resp_header.acknowledgment_number = self.recv.seq_num;

        // sent data but still unacked by remote
        let mut offset = seq_num.wrapping_sub(self.send.unacked_seq_num) as usize;
        if let Some(closed_at) = self.closed_at {
            if seq_num == closed_at.wrapping_add(1) {
                offset = 0;
                limit = 0;
            }
        }
        let (mut head, mut tail) = self.data_out.as_slices();
        if head.len() >= offset {
            head = &head[offset..]
        } else {
            let skipped = head.len();
            head = &[];
            tail = &tail[(offset - skipped)..]
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

        let n_data_bytes = {
            let mut written = 0;

            let head_end = min(limit, head.len());
            written += buf.write(&head[..head_end])?;
            limit -= written;

            let tail_end = min(limit, tail.len());
            written += buf.write(&tail[..tail_end])?;

            written
        };

        // println!("Connection.write => state: {:?}", self.state);
        // println!("Connection.write => seq_num: {seq_num}");
        // println!("Connection.write => n_data_bytes: {n_data_bytes}");

        let ip_payload_end_idx = buf.position() as usize;

        let buf = buf.get_mut();

        // finally we can calculate the tcp checksum and write out the tcp header
        self.tcp_resp_header.checksum = self
            .tcp_resp_header
            .calc_checksum_ipv4(
                &self.ip_resp_header,
                &mut buf[ip_header_end_idx..ip_payload_end_idx],
            )
            .expect("failed to compute checksum");

        let mut tcp_header_buf = &mut buf[ip_header_end_idx..tcp_header_end_idx];
        // tcp data has already been written, so we write just tcp header with calculated checksum
        self.tcp_resp_header.write(&mut tcp_header_buf)?;

        let mut next_seq_num = seq_num.wrapping_add(n_data_bytes as u32);
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

        dev.send(&buf[..ip_payload_end_idx])?;

        Ok(n_data_bytes)
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

        let incoming_seq_num = tcp_req_header.sequence_number();
        let window_end = self.recv.seq_num.wrapping_add(self.recv.window as u32);

        //   Segment Receive  Test
        //   Length  Window
        //   ------- -------  -------------------------------------------
        //
        //      0       0     SEG.SEQ = RCV.NXT (1 cond)
        //
        //      0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND (2 cond)
        //
        //     >0       0     not acceptable (3 cond)
        //
        //     >0      >0     RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND (4 cond)
        //                 or RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
        // self.recv.seq_num.wrapping_sub(1) turns "<" to "<=" inside "is_between_wrapped" function
        println!("Connection.handle_packet => self.state: {:?}", self.state);
        println!("Connection.handle_packet => self.recv.seq_num.wrapping_sub(1): {:?}", self.recv.seq_num.wrapping_sub(1));
        println!("Connection.handle_packet => incoming_seq_num: {incoming_seq_num}");
        println!("Connection.handle_packet => window_end: {window_end}");
        println!("Connection.handle_packet => self.recv.seq_num.wrapping_sub(1): {:?}", self.recv.seq_num.wrapping_sub(1));
        println!("Connection.handle_packet => data_len: {data_len}");
        println!("Connection.handle_packet => incoming_seq_num.wrapping_add(data_len - 1): {incoming_seq_num}");
        println!("Connection.handle_packet => window_end: {window_end}");
        let acceptable_incoming_seq_num = if data_len == 0 {
            println!("1");
            if self.recv.window == 0 {
                // 0 0 (1 cond)
                if incoming_seq_num == self.recv.seq_num {
                    println!("2");
                    true
                } else {
                    println!("3");
                    false
                }
                // 0 >0 (2 cond)
            } else if is_between_wrapped(
                self.recv.seq_num.wrapping_sub(1),
                incoming_seq_num,
                window_end,
            ) {
                println!("4");
                true
            } else {
                println!("5");
                false
            }
        } else {
            // >0 0 (3 cond)
            if self.recv.window == 0 {
                println!("6");
                false
            // The first part of this test checks to see if the beginning of the
            // segment falls in the window, the second part of the test checks to see
            // if the end of the segment falls in the window; if the segment passes
            // either part of the test it contains data in the window.
            // RCV.NXT =< SEG.SEQ < RCV.NXT+RCV.WND
            // RCV.NXT =< SEG.SEQ+SEG.LEN-1 < RCV.NXT+RCV.WND
            // >0 >0 (4 cond)
            } else if is_between_wrapped(
                self.recv.seq_num.wrapping_sub(1),
                incoming_seq_num,
                window_end,
            ) || is_between_wrapped(
                self.recv.seq_num.wrapping_sub(1),
                incoming_seq_num.wrapping_add(data_len - 1),
                window_end,
            ) {
                println!("7");
                true
            } else {
                println!("8");
                false
            }
        };
        
        // println!("Connection.handle_packet => acceptable_incoming_seq_num: {}", acceptable_incoming_seq_num);
        println!("Connection.handle_packet => self.send: {:?}", self.send);
        println!("Connection.handle_packet => self.recv: {:?}", self.recv);
        if !acceptable_incoming_seq_num {
            self.write(dev, self.send.seq_num, 0)?;
            return Ok(self.available_io());
        }
        println!("fixed!!!");
        if !tcp_req_header.ack() {
            if tcp_req_header.syn() {
                self.recv.seq_num = incoming_seq_num.wrapping_add(1);
            }
            return Ok(self.available_io());
        }

        let incoming_ack_num = tcp_req_header.acknowledgment_number();

        if let State::SynReceived = self.state {
            // SND.UNA =< SEG.ACK =< SND.NXT
            if is_between_wrapped(
                self.send.unacked_seq_num.wrapping_sub(1),
                incoming_ack_num,
                self.send.seq_num.wrapping_add(1),
            ) {
                // Remote must have acked our SYN, since we detected at least one acked byte,
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
            // self.send.seq_num.wrapping_add(1) makes seq_num inclusive in comparison.
            // Makes is_between_wrapped more generic.
            if is_between_wrapped(
                self.send.unacked_seq_num,
                incoming_ack_num,
                self.send.seq_num.wrapping_add(1),
            ) {
                if !self.data_out.is_empty() {
                    let data_start = if self.send.unacked_seq_num == self.send.init_seq_num {
                        // send.unacked_seq_num hasn't been updated yet with ACK for our SYN,
                        // so data starts just beyond it
                        self.send.unacked_seq_num.wrapping_add(1)
                    } else {
                        self.send.unacked_seq_num
                    };
                    let acked_data_len = min(
                        incoming_ack_num.wrapping_sub(data_start) as usize,
                        self.data_out.len(),
                    );

                    self.data_out.drain(..acked_data_len);

                    self.timers.send_times.retain(|seq_num, sent_at| {
                        if is_between_wrapped(
                            self.send.unacked_seq_num,
                            *seq_num,
                            incoming_ack_num
                        ) {
                            let round_trip_time = sent_at.elapsed();
                            // SRTT = (ALPHA * SRTT) + ((1-ALPHA) * RTT)
                            self.timers.smoothed_round_trip_time =
                                self.timers.smoothed_round_trip_time.mul_f64(0.8)
                                    + round_trip_time.mul_f64(1.0 - 0.8);
                            return false;
                        }
                        true
                    });
                }
                self.send.unacked_seq_num = incoming_ack_num;
            }
        }

        if let State::FinWait1 = self.state {
            if let Some(closed_at) = self.closed_at {
                if self.send.unacked_seq_num == closed_at.wrapping_add(1) {
                    // our FIN has been acked
                    self.state = State::FinWait2;
                }
            }
        }

        if !data.is_empty() {
            if let State::Established | State::FinWait1 | State::FinWait2 = self.state {
                let mut unread_data_idx = self.recv.seq_num.wrapping_sub(incoming_seq_num) as usize;
                if unread_data_idx > data_len as usize {
                    // We must have received a retransmitted FIN we have already seen.
                    // recv.seq_num points beyond FIN, but FIN is not in the data.
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

    pub fn tick<'a>(&mut self, dev: &mut Device) -> Result<()> {
        if let State::FinWait2 | State::TimeWait = self.state {
            // we have shut down our write side and the other side acked,
            // no need to (re)transmit anything
            return Ok(());
        }

        // println!("Connection.tick => ");
        // length of data which has been sent but not acked yet
        let unacked_len = self
            .closed_at
            .unwrap_or(self.send.seq_num)
            .wrapping_sub(self.send.unacked_seq_num);
        let unsent_len = self.data_out.len() - unacked_len as usize;

        // RFC: 793, section: 3.7
        // the oldest unacked seq
        let elapsed = self
            .timers
            .send_times
            .range(self.send.unacked_seq_num..)
            .next()
            .map(|val| val.1.elapsed());

        let should_retransmit = if let Some(elapsed) = elapsed {
            elapsed > Duration::from_secs(1)
                && elapsed > self.timers.smoothed_round_trip_time.mul_f32(1.5)
        } else {
            false
        };

        if should_retransmit {
            let resend_len = min(self.data_out.len(), self.send.window as usize);
            if resend_len < self.send.window as usize && self.is_closed {
                self.tcp_resp_header.fin = true;
                self.closed_at = Some(
                    self.send
                        .unacked_seq_num
                        .wrapping_add(self.data_out.len() as u32),
                );
            }
            self.write(dev, self.send.unacked_seq_num, resend_len)?;
        } else {
            // send new data

            if unsent_len == 0 && self.closed_at.is_some() {
                return Ok(());
            }

            // Amount of new data we are allowed to send,
            // which shouldn't exceed window size.
            // Takes into account data already sent but still unacked.
            let allowed_len = self.send.window as u32 - unacked_len;
            if allowed_len == 0 {
                return Ok(());
            }

            let send_len = min(unsent_len as u32, allowed_len);
            if send_len < allowed_len && self.is_closed && self.closed_at.is_none() {
                self.tcp_resp_header.fin = true;
                self.closed_at = Some(
                    self.send
                        .unacked_seq_num
                        .wrapping_add(self.data_out.len() as u32),
                );
            }

            self.write(dev, self.send.seq_num, send_len as usize)?;
        }
        // If no SENDs have been issued and there is no pending data to send,
        // then form a FIN segment and send it, and enter FIN-WAIT-1 state;
        // otherwise queue for processing after entering ESTABLISHED state.
        Ok(())
    }

    #[allow(dead_code)]
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

    pub(crate) fn is_time_wait(&self) -> bool {
        if let State::TimeWait = self.state {
            return true;
        }
        false
    }

    fn available_io(&self) -> AvailableIo {
        let mut aio = AvailableIo::new();
        if self.is_time_wait() || !self.data_in.is_empty() {
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

// fn is_between_wrapped(start: u32, between: u32, end: u32) -> bool {
//     if start == between {
//         return false;
//     }
//     // if start < between then end shouldn't be between them:
//     // 0...start...between...end...u32::MAX -> OK
//     // 0...end...start...between...u32::MAX -> OK
//     // 0...start...end...between...u32::MAX -> not OK
//     if start < between {
//         if start <= end && end <= between {
//             return false;
//         }
//         // if between < start then end should be between them:
//         // 0...between...end...start...u32::MAX -> OK
//         // 0...end...between...start...u32::MAX -> not OK
//         // 0...between...start...end...u32::MAX -> not OK
//     } else {
//         if !(between < end && end < start) {
//             return false;
//         }
//     }
//     true
// }

fn wrapping_less_than(lhs: u32, rhs: u32) -> bool {
    // From RFC1323:
    // TCP determines if a data segment is "old" or "new" by testing
    // whether its sequence number is within 2**31 bytes of the left edge
    // of the window, and if it is not, discarding the data as "old". To
    // ensure that new data is never mistakenly considered old and vice-
    // versa, the left edge of the sender's window has to be at most
    // 2**31 away from the right edge of the receiver's window.
    //
    // u32 max value = 4,294,967,295
    // 1 << 31 = 2,147,483,648
    // 50 - 60 = 4,294,967,286 > 2,147,483,648
    // 4,294,967,000 - 150 = 4,294,966,850 > 2,147,483,648
    lhs.wrapping_sub(rhs) > (1 << 31)
}

fn is_between_wrapped(start: u32, between: u32, end: u32) -> bool {
    wrapping_less_than(start, between) && wrapping_less_than(between, end)
}
