use anyhow::Result;
use num_enum::IntoPrimitive;
use polling::PollMode;
use polling::os::kqueue::PollerKqueueExt;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::io::RawFd;
use std::time::Duration;

pub struct Poller<'poller> {
    poller: polling::Poller,
    events: polling::Events,
    timeout: Duration,
    last_periodic_tick: coarsetime::Instant,
    vm_fd: BorrowedFd<'poller>,
    host_fd: BorrowedFd<'poller>,
    control_fd: Option<BorrowedFd<'poller>>,
}

#[derive(IntoPrimitive)]
#[repr(usize)]
enum EventKey {
    VM,
    Host,
    Control,
    Interrupt,
}

impl Poller<'_> {
    pub fn new<'poller>(
        vm_fd: RawFd,
        host_fd: RawFd,
        control_fd: Option<RawFd>,
        timeout: Duration,
    ) -> Result<Poller<'poller>> {
        let poller = polling::Poller::new()?;

        Ok(Poller {
            poller,
            events: polling::Events::new(),
            timeout,
            last_periodic_tick: coarsetime::Instant::recent(),
            vm_fd: unsafe { BorrowedFd::borrow_raw(vm_fd) },
            host_fd: unsafe { BorrowedFd::borrow_raw(host_fd) },
            control_fd: control_fd.map(|fd| unsafe { BorrowedFd::borrow_raw(fd) }),
        })
    }

    pub fn arm(&self) -> Result<()> {
        unsafe {
            self.poller.add_with_mode(
                self.vm_fd.as_raw_fd(),
                self.vm_interest(),
                PollMode::Edge,
            )?;

            if let Some(control_fd) = self.control_fd {
                self.poller.add_with_mode(
                    control_fd.as_raw_fd(),
                    polling::Event::all(EventKey::Control.into()),
                    PollMode::Edge,
                )?;
            }
            self.poller.add_with_mode(
                self.host_fd.as_raw_fd(),
                self.host_interest(),
                PollMode::Edge,
            )?;
        }

        let interrupt_signal = polling::os::kqueue::Signal(libc::SIGINT);
        self.poller
            .add_filter(interrupt_signal, EventKey::Interrupt.into(), PollMode::Edge)?;

        Ok(())
    }

    pub fn rearm(&mut self) {
        self.events.clear();
    }

    pub fn wait(&mut self) -> Result<(bool, bool, bool)> {
        self.poller.wait(&mut self.events, Some(self.timeout))?;

        let vm_readable = self
            .events
            .iter()
            .any(|ev| ev.key == Into::<usize>::into(EventKey::VM));
        let host_readable = self
            .events
            .iter()
            .any(|ev| ev.key == Into::<usize>::into(EventKey::Host));
        let interrupt = self
            .events
            .iter()
            .any(|ev| ev.key == Into::<usize>::into(EventKey::Interrupt));
        Ok((vm_readable, host_readable, interrupt))
    }

    pub fn periodic_tick_due(&mut self) -> bool {
        let due = self.last_periodic_tick.elapsed_since_recent() >= self.timeout.into();

        if due {
            self.last_periodic_tick = coarsetime::Instant::recent();
        }

        due
    }

    pub fn remove_control(&mut self) -> Result<()> {
        if let Some(control_fd) = self.control_fd.take() {
            self.poller.delete(control_fd)?;
        }

        Ok(())
    }

    fn vm_interest(&self) -> polling::Event {
        polling::Event::readable(EventKey::VM.into())
    }

    fn host_interest(&self) -> polling::Event {
        polling::Event::readable(EventKey::Host.into())
    }
}
