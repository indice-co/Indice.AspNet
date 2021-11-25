﻿using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Moq;
using Xunit;

namespace Indice.Services.Tests
{
    public class PushNotificationMessageTests
    {
        [Fact]
        public async Task PushNotificationBuilderTestMessage() {
            // Arrange
            var service = new Mock<IPushNotificationService>();
            var pushNotificationBuilder = new PushNotificationMessageBuilder()
                .To("5372ef3e-9bf8-464d-8fc9-3234a2b979f6")
                .WithToken("123456")
                .WithMessage("This is the message!");

            // Act
            await service.Object.SendAsync(_ => pushNotificationBuilder);

            // Assert
            service.Verify(p => p.SendAsync(
                It.Is<string>(value => value == "This is the message!"),
                It.Is<IList<string>>(value => value.SingleOrDefault() == "5372ef3e-9bf8-464d-8fc9-3234a2b979f6"),
                It.Is<string>(value => value == "123456"),
                It.IsAny<string>()
                ), Times.Once);
        }

        [Fact]
        public async Task PushNotificationBuilderTestData() {
            // Arrange
            var service = new Mock<IPushNotificationService>();
            var pushNotificationBuilder = new PushNotificationMessageBuilder()
                .To("5372ef3e-9bf8-464d-8fc9-3234a2b979f6")
                .WithToken("123456")
                .WithMessage("This is the message!")
                .WithData("{{\"connectionId\":\"1234-ab-cd\", \"otp\":{0}}}");

            // Act
            await service.Object.SendAsync(_ => pushNotificationBuilder);

            // Assert
            service.Verify(p => p.SendAsync(
                It.Is<string>(value => value == "This is the message!"),
                It.Is<IList<string>>(value => value.SingleOrDefault() == "5372ef3e-9bf8-464d-8fc9-3234a2b979f6"),
                It.Is<string>(value => value == "{\"connectionId\":\"1234-ab-cd\", \"otp\":123456}"),
                It.IsAny<string>()
            ), Times.Once);
        }

        [Fact]
        public async Task PushNotificationBuilderTestClassification() {
            // Arrange
            var service = new Mock<IPushNotificationService>();
            var pushNotificationBuilder = new PushNotificationMessageBuilder()
                .To("5372ef3e-9bf8-464d-8fc9-3234a2b979f6")
                .WithToken("123456")
                .WithMessage("This is the message!")
                .WithClassification("Approvals");

            // Act
            await service.Object.SendAsync(_ => pushNotificationBuilder);

            // Assert
            service.Verify(p => p.SendAsync(
                It.Is<string>(value => value == "This is the message!"),
                It.Is<IList<string>>(value => value.SingleOrDefault() == "5372ef3e-9bf8-464d-8fc9-3234a2b979f6"),
                It.Is<string>(value => value == "123456"),
                It.Is<string>(value => value == "Approvals")
                ), Times.Once);
        }

        [Fact]
        public async Task PushNotificationBuilderTestTags() {
            // Arrange
            var service = new Mock<IPushNotificationService>();
            var pushNotificationBuilder = new PushNotificationMessageBuilder()
                .To("5372ef3e-9bf8-464d-8fc9-3234a2b979f6")
                .WithToken("123456")
                .WithMessage("This is the message!")
                .WithTags("tag-1", "tag-2");

            // Act
            await service.Object.SendAsync(_ => pushNotificationBuilder);

            // Assert
            service.Verify(p => p.SendAsync(
                It.Is<string>(value => value == "This is the message!"),
                It.Is<IList<string>>(value => value.ElementAt(0) == "5372ef3e-9bf8-464d-8fc9-3234a2b979f6" && value.ElementAt(1) == "tag-1" && value.ElementAt(2) == "tag-2"),
                It.Is<string>(value => value == "123456"),
                It.IsAny<string>()
                ), Times.Once);
        }
    }
}