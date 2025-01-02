import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';

@Schema()
export class Emails {
  @Prop({ required: true, default: [] })
  listId: string[];

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({
    enum: ['Deliverable', 'Undeliverable', 'Risky'],
    required: true,
  })
  state: 'Deliverable' | 'Undeliverable' | 'Risky';

  @Prop({ required: true, default: 0 })
  score: number;

  @Prop({default: ""})
  SmtpProvider: string;

  @Prop({ required: true })
  time: Date;
  @Prop({ required: true })
  disposable: boolean;

  @Prop({
    enum: ['Free', 'Paid'],
    required: true,
  })
  free: 'Free' | 'Paid';

  @Prop({
    enum: ['Yes', 'No'],
    required: true,
  })
  role: 'Yes' | 'No';

  @Prop()
  mxRecords: string[];
}

export const EmailsSchema = SchemaFactory.createForClass(Emails);
