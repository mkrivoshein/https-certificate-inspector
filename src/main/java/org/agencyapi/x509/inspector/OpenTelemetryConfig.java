package org.agencyapi.x509.inspector;

import io.micrometer.tracing.otel.bridge.CompositeSpanExporter;
import io.micrometer.tracing.otel.bridge.OtelCurrentTraceContext;
import io.micrometer.tracing.otel.bridge.OtelPropagator;
import io.micrometer.tracing.otel.bridge.OtelTracer;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.resources.Resource;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import io.opentelemetry.semconv.ServiceAttributes;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenTelemetryConfig {

    @Value("${spring.application.name:certificate-inspector}")
    private String applicationName;

    @Bean
    public OpenTelemetry openTelemetry() {
        var resource = Resource.getDefault()
                .merge(Resource.create(
                        io.opentelemetry.api.common.Attributes.of(
                                ServiceAttributes.SERVICE_NAME, applicationName)));

        var sdkTracerProvider = SdkTracerProvider.builder()
                .addSpanProcessor(SimpleSpanProcessor.create(new CompositeSpanExporter(null, null, null, null)))
                .setResource(resource)
                .build();

        return OpenTelemetrySdk.builder()
                .setTracerProvider(sdkTracerProvider)
                .setPropagators(ContextPropagators.noop())
                .build();
    }

    @Bean
    public Tracer otelTracer(OpenTelemetry openTelemetry) {
        return openTelemetry.getTracer(applicationName);
    }

    @Bean
    public OtelCurrentTraceContext otelCurrentTraceContext() {
        return new OtelCurrentTraceContext();
    }

    @Bean
    public OtelTracer.EventPublisher eventPublisher(ApplicationEventPublisher applicationEventPublisher) {
        //TODO: replace with a logger
        return applicationEventPublisher::publishEvent;
    }

    @Bean
    public io.micrometer.tracing.Tracer micrometerTracer(
            Tracer otelTracer,
            OtelCurrentTraceContext otelCurrentTraceContext,
            OtelTracer.EventPublisher eventPublisher) {

        // Using the 3-argument constructor (no baggage support)
        return new OtelTracer(
                otelTracer,
                otelCurrentTraceContext,
                eventPublisher);
    }
}