use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};
use chrono::{Local, NaiveDate};
use innerwarden_core::{event::Event, incident::Incident};

pub struct JsonlWriter {
    data_dir: PathBuf,
    write_events: bool,
    events_writer: Option<DatedWriter>,
    incidents_writer: Option<DatedWriter>,
}

struct DatedWriter {
    writer: BufWriter<File>,
    date: NaiveDate,
}

impl JsonlWriter {
    pub fn new(data_dir: impl Into<PathBuf>, write_events: bool) -> Result<Self> {
        let data_dir = data_dir.into();
        std::fs::create_dir_all(&data_dir)
            .with_context(|| format!("failed to create data dir: {}", data_dir.display()))?;
        Ok(Self { data_dir, write_events, events_writer: None, incidents_writer: None })
    }

    pub fn write_event(&mut self, event: &Event) -> Result<()> {
        if !self.write_events {
            return Ok(());
        }
        let today = Local::now().date_naive();
        let w = self.events_writer(today)?;
        let line = serde_json::to_string(event)?;
        writeln!(w.writer, "{line}")?;
        Ok(())
    }

    pub fn write_incident(&mut self, incident: &Incident) -> Result<()> {
        let today = Local::now().date_naive();
        let w = self.incidents_writer(today)?;
        let line = serde_json::to_string(incident)?;
        writeln!(w.writer, "{line}")?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<()> {
        if let Some(w) = &mut self.events_writer {
            w.writer.flush()?;
        }
        if let Some(w) = &mut self.incidents_writer {
            w.writer.flush()?;
        }
        Ok(())
    }

    fn events_writer(&mut self, today: NaiveDate) -> Result<&mut DatedWriter> {
        if self.events_writer.as_ref().map_or(true, |w| w.date != today) {
            let path = self.data_dir.join(format!("events-{}.jsonl", today.format("%Y-%m-%d")));
            self.events_writer = Some(DatedWriter::open(path, today)?);
        }
        Ok(self.events_writer.as_mut().unwrap())
    }

    fn incidents_writer(&mut self, today: NaiveDate) -> Result<&mut DatedWriter> {
        if self.incidents_writer.as_ref().map_or(true, |w| w.date != today) {
            let path =
                self.data_dir.join(format!("incidents-{}.jsonl", today.format("%Y-%m-%d")));
            self.incidents_writer = Some(DatedWriter::open(path, today)?);
        }
        Ok(self.incidents_writer.as_mut().unwrap())
    }
}

impl Drop for JsonlWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

impl DatedWriter {
    fn open(path: PathBuf, date: NaiveDate) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("failed to open {}", path.display()))?;
        Ok(Self { writer: BufWriter::new(file), date })
    }
}
