import { Module } from '@nestjs/common';
import { EmailCheckerController } from './email-checker.controller';
import { EmailCheckerService } from './email-checker.service';
import { MongooseModule } from '@nestjs/mongoose';
import { Emails, EmailsSchema } from './schemas/emails.schema';
import { Users, UsersSchema } from './schemas/users.schema';

@Module({
  imports: [
    MongooseModule.forFeature([
      {
        name: Emails.name,
        schema: EmailsSchema,
      },
      {
        name: Users.name,
        schema: UsersSchema,
      },
    ]),
  ],
  controllers: [EmailCheckerController],
  providers: [EmailCheckerService],
})
export class EmailCheckerModule {}
