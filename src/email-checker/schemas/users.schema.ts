import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Types } from 'mongoose';
import { Emails } from './emails.schema';

@Schema()
class ListItem {
  @Prop({ type: Types.ObjectId, ref: Emails.name, required: true })
  id: string;

  @Prop({ type: String, required: true })
  name: string;
}

const ListItemSchema = SchemaFactory.createForClass(ListItem);

@Schema()
export class Users {
  @Prop({ required: true, unique: true })
  email: string;
  
  @Prop({ default: '' })
  username: string;
  
  @Prop({ type: [ListItemSchema], default: [] })
  listsIds: ListItem[];

  @Prop({ type: [{ type: Types.ObjectId, ref: Emails.name }], default: [] })
  singlesIds: string[];

  @Prop({default: ''})
  hashPassword: string;
}

export const UsersSchema = SchemaFactory.createForClass(Users);
