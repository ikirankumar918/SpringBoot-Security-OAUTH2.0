package com.dailycodebuffer.Oauthresourceserver.dto;

import java.util.UUID;

public record OrderDto(
        UUID orderId,
        String orderType
    )
{

}
