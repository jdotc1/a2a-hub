package dev.a2ahub.config;

import dev.a2ahub.security.SecurityProperties;
import org.junit.jupiter.api.Test;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.simp.stomp.StompCommand;
import org.springframework.messaging.simp.stomp.StompHeaderAccessor;
import org.springframework.messaging.support.MessageBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class WebSocketInboundAuthenticationTest {

    private final MessageChannel channel = mock(MessageChannel.class);

    private Message<byte[]> stomp(StompCommand command, String header, String value) {
        StompHeaderAccessor accessor = StompHeaderAccessor.create(command);
        if (header != null) accessor.addNativeHeader(header, value);
        accessor.setLeaveMutable(true);
        return MessageBuilder.createMessage(new byte[0], accessor.getMessageHeaders());
    }

    @Test
    void publicReadsAllowConnectWithoutCredentials() {
        SecurityProperties props = new SecurityProperties();
        props.setApiKey("expected-key");
        props.setRequireAuthForReads(false);
        Message<byte[]> message = stomp(StompCommand.CONNECT, null, null);
        assertThat(new WebSocketConfig(props).inboundAuthInterceptor().preSend(message, channel))
                .isSameAs(message);
    }

    @Test
    void protectedReadsRejectMissingOrInvalidKey() {
        SecurityProperties props = new SecurityProperties();
        props.setApiKey("expected-key");
        props.setRequireAuthForReads(true);
        var interceptor = new WebSocketConfig(props).inboundAuthInterceptor();
        assertThatThrownBy(() -> interceptor.preSend(stomp(StompCommand.CONNECT, null, null), channel))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> interceptor.preSend(stomp(StompCommand.CONNECT, "X-API-Key", "bad"), channel))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> interceptor.preSend(stomp(StompCommand.CONNECT, "Authorization", "Bearer bad"), channel))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void protectedReadsAcceptApiKeyOrBearerToken() {
        SecurityProperties props = new SecurityProperties();
        props.setApiKey("expected-key");
        props.setRequireAuthForReads(true);
        var interceptor = new WebSocketConfig(props).inboundAuthInterceptor();
        for (Message<byte[]> message : java.util.List.of(
                stomp(StompCommand.CONNECT, "X-API-Key", "expected-key"),
                stomp(StompCommand.CONNECT, "Authorization", "Bearer expected-key"))) {
            assertThat(interceptor.preSend(message, channel)).isSameAs(message);
        }
    }

    @Test
    void noConfiguredKeyKeepsOpenModeAndNonConnectFramesUnchanged() {
        SecurityProperties props = new SecurityProperties();
        props.setRequireAuthForReads(true);
        var interceptor = new WebSocketConfig(props).inboundAuthInterceptor();
        Message<byte[]> connect = stomp(StompCommand.CONNECT, null, null);
        assertThat(interceptor.preSend(connect, channel)).isSameAs(connect);
        props.setApiKey("expected-key");
        Message<byte[]> subscribe = stomp(StompCommand.SUBSCRIBE, null, null);
        assertThat(interceptor.preSend(subscribe, channel)).isSameAs(subscribe);
    }
}
