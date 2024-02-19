use std::time::Duration;
use ironrdp::cliprdr::backend::{ClipboardMessage, CliprdrBackendFactory};
use ironrdp::connector::{ConnectionResult, ConnectorResult};
use ironrdp::graphics::image_processing::PixelFormat;
use ironrdp::pdu::input::fast_path::FastPathInputEvent;
use ironrdp::session::image::DecodedImage;
use ironrdp::session::{ActiveStage, ActiveStageOutput, GracefulDisconnectReason, SessionResult};
use ironrdp::{cliprdr, connector, rdpdr, rdpsnd, session};
use rdpdr::NoopRdpdrBackend;
use smallvec::SmallVec;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant;
use winit::event_loop::EventLoopProxy;
use ironrdp::pdu::{dvc, PduParsing};
use ironrdp::pdu::dvc::display::{Monitor, MonitorFlags, Orientation};
use ironrdp::pdu::write_buf::WriteBuf;
use ironrdp::pdu::rdp::vc::dvc::display::ClientPdu;
use crate::rdp::dvc::display::MonitorLayoutPdu;

use crate::config::Config;

#[derive(Debug)]
pub enum RdpOutputEvent {
    Image { buffer: Vec<u32>, width: u16, height: u16 },
    ConnectionFailure(connector::ConnectorError),
    PointerDefault,
    PointerHidden,
    PointerPosition { x: u16, y: u16 },
    Terminated(SessionResult<GracefulDisconnectReason>),
}

#[derive(Debug)]
pub enum RdpInputEvent {
    Resize { width: u16, height: u16 },
    FastPath(SmallVec<[FastPathInputEvent; 2]>),
    Close,
    Clipboard(ClipboardMessage),
}

impl RdpInputEvent {
    pub fn create_channel() -> (mpsc::UnboundedSender<Self>, mpsc::UnboundedReceiver<Self>) {
        mpsc::unbounded_channel()
    }
}

pub struct RdpClient {
    pub config: Config,
    pub event_loop_proxy: EventLoopProxy<RdpOutputEvent>,
    pub input_event_receiver: mpsc::UnboundedReceiver<RdpInputEvent>,
    pub cliprdr_factory: Option<Box<dyn CliprdrBackendFactory + Send>>,
}

impl RdpClient {
    pub async fn run(mut self) {
        loop {
            let (connection_result, framed) = match connect(&self.config, self.cliprdr_factory.as_deref()).await {
                Ok(result) => result,
                Err(e) => {
                    let _ = self.event_loop_proxy.send_event(RdpOutputEvent::ConnectionFailure(e));
                    break;
                }
            };

            match self.active_session(
                framed,
                connection_result,
            )
                .await
            {
                Ok(RdpControlFlow::ReconnectWithNewSize { width, height }) => {
                    self.config.connector.desktop_size.width = width;
                    self.config.connector.desktop_size.height = height;
                }
                Ok(RdpControlFlow::TerminatedGracefully(reason)) => {
                    let _ = self.event_loop_proxy.send_event(RdpOutputEvent::Terminated(Ok(reason)));
                    break;
                }
                Err(e) => {
                    let _ = self.event_loop_proxy.send_event(RdpOutputEvent::Terminated(Err(e)));
                    break;
                }
            }
        }
    }

    async fn active_session(
        &mut self,
        mut framed: UpgradedFramed,
        connection_result: ConnectionResult,
    ) -> SessionResult<RdpControlFlow> {
        let mut image = DecodedImage::new(
            PixelFormat::RgbA32,
            connection_result.desktop_size.width,
            connection_result.desktop_size.height,
        );

        let mut width = connection_result.desktop_size.width;
        let mut height = connection_result.desktop_size.height;

        info!(width=connection_result.desktop_size.width, height=connection_result.desktop_size.height, "image");
        info!(width=self.config.connector.desktop_size.width, height=self.config.connector.desktop_size.height, "image");

        let mut active_stage = ActiveStage::new(connection_result, None);

        let mut resize = None;
        let resize_debounce = tokio::time::sleep(Duration::from_millis(0));
        tokio::pin!(resize_debounce);

        let disconnect_reason = 'outer: loop {
            let outputs = tokio::select! {
            () = &mut resize_debounce, if resize.is_some() => {
                (width, height) = resize.unwrap();
                 width = std::cmp::max((width>>2)<<2, 200);
                 height = std::cmp::max((height>>2)<<2, 200);

                let mut buf = WriteBuf::new();
                let monitorLayoutPdu = ClientPdu::DisplayControlMonitorLayout(MonitorLayoutPdu {
                    monitors: vec![Monitor {
                        flags: MonitorFlags::PRIMARY,
                        left: 0,
                        top: 0,
                        width: width as u32,
                        height: height as u32,
                        physical_width: width as u32,
                        physical_height: height as u32,
                        orientation: Orientation::Landscape,
                        desktop_scale_factor: 100,
                        device_scale_factor: 100,
                    }]
                });
                monitorLayoutPdu.to_buffer(&mut buf);

                let mut buf2 = WriteBuf::new();
                let mut res = vec![];
                if active_stage.encode_dynamic(&mut buf2, dvc::display::CHANNEL_NAME, buf.filled()).is_ok() {
                        res.push(ActiveStageOutput::ResponseFrame(buf2.filled().to_vec()));
                }
                width = std::cmp::max(width, image.width());
                height = std::cmp::max(height, image.height());
                info!(width, height, "resize event");
                image = DecodedImage::new(
                    PixelFormat::RgbA32,
                    width,
                    height,
                );
                resize = None;
                res
            }
            frame = framed.read_pdu() => {
                let (action, payload) = frame.map_err(|e| session::custom_err!("read frame", e))?;
                trace!(?action, frame_length = payload.len(), "Frame received");

                active_stage.process(&mut image, action, &payload)?
            }
            input_event = self.input_event_receiver.recv() => {
                let input_event = input_event.ok_or_else(|| session::general_err!("GUI is stopped"))?;

                    let mut seen = false;
                match input_event {
                    RdpInputEvent::Resize { mut width, mut height } => {
                        resize = Some((width, height));
                        resize_debounce.as_mut().reset(Instant::now() + Duration::from_millis(500));
                        Vec::new()
                    },
                    RdpInputEvent::FastPath(events) => {
                        trace!(?events);
                        active_stage.process_fastpath_input(&mut image, &events)?
                    }
                    RdpInputEvent::Close => {
                        active_stage.graceful_shutdown()?
                    }
                    RdpInputEvent::Clipboard(event) => {
                        if let Some(cliprdr) = active_stage.get_svc_processor::<ironrdp::cliprdr::CliprdrClient>() {
                            if let Some(svc_messages) = match event {
                                ClipboardMessage::SendInitiateCopy(formats) => {
                                    Some(cliprdr.initiate_copy(&formats)
                                        .map_err(|e| session::custom_err!("CLIPRDR", e))?)
                                }
                                ClipboardMessage::SendFormatData(response) => {
                                    Some(cliprdr.submit_format_data(response)
                                    .map_err(|e| session::custom_err!("CLIPRDR", e))?)
                                }
                                ClipboardMessage::SendInitiatePaste(format) => {
                                    Some(cliprdr.initiate_paste(format)
                                        .map_err(|e| session::custom_err!("CLIPRDR", e))?)
                                }
                                ClipboardMessage::Error(e) => {
                                    error!("Clipboard backend error: {}", e);
                                    None
                                }
                            } {
                                let frame = active_stage.process_svc_processor_messages(svc_messages)?;
                                // Send the messages to the server
                                vec![ActiveStageOutput::ResponseFrame(frame)]
                            } else {
                                // No messages to send to the server
                                Vec::new()
                            }
                        } else  {
                            warn!("Clipboard event received, but Cliprdr is not available");
                            Vec::new()
                        }
                    }
                }
            }
        };

            for out in outputs {
                match out {
                    ActiveStageOutput::AutoReconnectInfo(reconnect) =>
                        self.config.connector.auto_reconnect = Some(reconnect),
                    ActiveStageOutput::ResponseFrame(frame) => framed
                        .write_all(&frame)
                        .await
                        .map_err(|e| session::custom_err!("write response", e))?,
                    ActiveStageOutput::GraphicsUpdate(_region) => {
                        let buffer: Vec<u32> = image
                            .data()
                            .chunks_exact(4)
                            .map(|pixel| {
                                let r = pixel[0];
                                let g = pixel[1];
                                let b = pixel[2];
                                u32::from_be_bytes([0, r, g, b])
                            })
                            .collect();

                        self.event_loop_proxy
                            .send_event(RdpOutputEvent::Image {
                                buffer,
                                width,
                                height,
                            })
                            .map_err(|e| session::custom_err!("event_loop_proxy", e))?;
                    }
                    ActiveStageOutput::PointerDefault => {
                        self.event_loop_proxy
                            .send_event(RdpOutputEvent::PointerDefault)
                            .map_err(|e| session::custom_err!("event_loop_proxy", e))?;
                    }
                    ActiveStageOutput::PointerHidden => {
                        self.event_loop_proxy
                            .send_event(RdpOutputEvent::PointerHidden)
                            .map_err(|e| session::custom_err!("event_loop_proxy", e))?;
                    }
                    ActiveStageOutput::PointerPosition { x, y } => {
                        self.event_loop_proxy
                            .send_event(RdpOutputEvent::PointerPosition { x, y })
                            .map_err(|e| session::custom_err!("event_loop_proxy", e))?;
                    }
                    ActiveStageOutput::PointerBitmap(_) => {
                        // Not applicable, because we use the software cursor rendering.
                    }
                    ActiveStageOutput::Terminate(reason) => {
                        break 'outer reason
                    },
                }
            }
        };

        Ok(RdpControlFlow::TerminatedGracefully(disconnect_reason))
    }
}

enum RdpControlFlow {
    ReconnectWithNewSize { width: u16, height: u16 },
    TerminatedGracefully(GracefulDisconnectReason),
}

type UpgradedFramed = ironrdp_tokio::TokioFramed<ironrdp_tls::TlsStream<TcpStream>>;

async fn connect(
    config: &Config,
    cliprdr_factory: Option<&(dyn CliprdrBackendFactory + Send)>,
) -> ConnectorResult<(ConnectionResult, UpgradedFramed)> {
    let server_addr = config
        .destination
        .lookup_addr()
        .map_err(|e| connector::custom_err!("lookup addr", e))?;

    let stream = TcpStream::connect(&server_addr)
        .await
        .map_err(|e| connector::custom_err!("TCP connect", e))?;

    let mut framed = ironrdp_tokio::TokioFramed::new(stream);

    let mut connector = connector::ClientConnector::new(config.connector.clone())
        .with_server_addr(server_addr)
        // .with_static_channel(ironrdp::dvc::DrdynvcClient::new())
        .with_static_channel(rdpsnd::Rdpsnd::new())
        .with_static_channel(rdpdr::Rdpdr::new(Box::new(NoopRdpdrBackend {}), "IronRDP".to_owned()).with_smartcard(0));

    if let Some(builder) = cliprdr_factory {
        let backend = builder.build_cliprdr_backend();

        let cliprdr = cliprdr::Cliprdr::new(backend);

        connector.attach_static_channel(cliprdr);
    }

    let should_upgrade = ironrdp_tokio::connect_begin(&mut framed, &mut connector).await?;

    debug!("TLS upgrade");

    // Ensure there is no leftover
    let initial_stream = framed.into_inner_no_leftover();

    let (upgraded_stream, server_public_key) = ironrdp_tls::upgrade(initial_stream, config.destination.name())
        .await
        .map_err(|e| connector::custom_err!("TLS upgrade", e))?;

    let upgraded = ironrdp_tokio::mark_as_upgraded(should_upgrade, &mut connector);

    let mut upgraded_framed = ironrdp_tokio::TokioFramed::new(upgraded_stream);

    let mut network_client = crate::network_client::ReqwestNetworkClient::new();
    let connection_result = ironrdp_tokio::connect_finalize(
        upgraded,
        &mut upgraded_framed,
        connector,
        (&config.destination).into(),
        server_public_key,
        Some(&mut network_client),
        None,
    )
        .await?;

    debug!(?connection_result);

    Ok((connection_result, upgraded_framed))
}
