import { CognitoIdentityProviderClient } from '@aws-sdk/client-cognito-identity-provider';
import { DynamicModule, Module } from '@nestjs/common';
import { moduleFactory } from '@onivoro/server-common';
import { ServerAwsCognitoConfig } from './server-aws-cognito-config.class';
import { CognitoTokenValidatorService } from './services/cognito-token-validator.service';
import { CognitoRefreshTokenService } from './services/cognito-refresh-token.service';

@Module({})
export class ServerAwsCognitoModule {
  static configure(config: ServerAwsCognitoConfig): DynamicModule {
    return moduleFactory({
      providers: [
        {
          provide: ServerAwsCognitoConfig,
          useValue: config,
        },
        {
          provide: CognitoIdentityProviderClient,
          useFactory: () => new CognitoIdentityProviderClient({
            region: config.AWS_REGION,
            apiVersion: config.COGNITO_API_VERSION
          })
        },
        CognitoTokenValidatorService,
        CognitoRefreshTokenService,
      ],
      module: ServerAwsCognitoModule,
    });
  }
}
