import { Module } from '@nestjs/common';
import { EmailCheckerModule } from './email-checker/email-checker.module';
import { MongooseModule } from '@nestjs/mongoose';
import { UsersModule } from './users/users.module';

@Module({
  imports: [
    EmailCheckerModule,
    MongooseModule.forRootAsync({
      useFactory: () => ({
        uri: 'mongodb+srv://mhaddaou:mhaddaou@cluster0.e9l52.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0',
      }),
    }),
    UsersModule,
  ],
  controllers: [],
  providers: [],
})
export class AppModule {}
